// Citeable — on-site technical audit. Vercel serverless function.
// POST /api/scan  { "domain": "example.com" }
//
// Measures on-site signals only. It does NOT estimate AI visibility or what
// any assistant says about the business; those require manual query testing.

const dns = require('dns').promises;
const net = require('net');

const UA = 'CiteableBot/1.0 (+https://citeable.com)';
const TIMEOUT_MS = 7000;
const MAX_BYTES = 1_500_000;
const REDIRECT_CODES = [301, 302, 303, 307, 308];

// Crawlers whose blocking matters for AI answers. `critical` = blocking it
// removes the business from that assistant's index.
const AI_BOTS = [
  { name: 'GPTBot', operator: 'OpenAI training', critical: true },
  { name: 'OAI-SearchBot', operator: 'OpenAI search', critical: true },
  { name: 'ClaudeBot', operator: 'Anthropic', critical: true },
  { name: 'PerplexityBot', operator: 'Perplexity', critical: true },
  { name: 'Google-Extended', operator: 'Google AI training', critical: false },
  { name: 'Bingbot', operator: 'Bing and Copilot', critical: false },
];

const CATEGORY_ORDER = [
  'Crawler access',
  'Renderability',
  'Facts on the page',
  'Structured data',
  'AI-readable files',
  'On-page basics',
];

const NOT_CHECKED = [
  'Whether ChatGPT, Perplexity, Gemini, Claude, or Google AI Overviews name or cite this business. That requires running real queries and recording the answers.',
  'Off-site signals: Google Business Profile, review platforms, directory listings, mentions on other sites, Wikipedia and Wikidata.',
  'Pages other than the homepage. This scan reads the homepage plus robots.txt, sitemap.xml, and llms.txt.',
  'Whether schema matches the visible content. Checked manually during the audit.',
  'Page speed, mobile layout, and internal linking.',
];

// ---------- input and network safety ----------

function cleanDomain(raw) {
  if (typeof raw !== 'string') return null;
  const d = raw.trim().toLowerCase()
    .replace(/^https?:\/\//, '').replace(/^www\./, '').split(/[/?#]/)[0];
  return /^(?=.{4,253}$)([a-z0-9-]+\.)+[a-z]{2,63}$/.test(d) ? d : null;
}

function isPrivateIp(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    return a === 0 || a === 10 || a === 127 || a >= 224 ||
      (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127);
  }
  if (net.isIPv6(ip)) {
    const l = ip.toLowerCase();
    return l === '::1' || l === '::' || l.startsWith('::ffff:') ||
      /^f[cd]/.test(l) || /^fe[89ab]/.test(l);
  }
  return true;
}

async function assertPublicHost(hostname) {
  if (hostname === 'localhost' || hostname.endsWith('.local') || hostname.endsWith('.internal')) {
    throw new Error('blocked host');
  }
  const addrs = await dns.lookup(hostname, { all: true });
  if (!addrs.length || addrs.some((a) => isPrivateIp(a.address))) throw new Error('blocked host');
}

// Fetches one file. Follows up to 3 redirects, re-checking each host so a
// redirect cannot send the scanner to an internal address.
async function getFile(url, hops = 0) {
  let u;
  try {
    u = new URL(url);
    await assertPublicHost(u.hostname);
  } catch {
    return { ok: false, status: 0, error: 'address not allowed', text: '', contentType: '' };
  }
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
  try {
    const r = await fetch(u, {
      redirect: 'manual',
      signal: ctrl.signal,
      headers: { 'User-Agent': UA, Accept: '*/*' },
    });
    const loc = r.headers.get('location');
    if (REDIRECT_CODES.includes(r.status) && loc && hops < 3) {
      return getFile(new URL(loc, u).toString(), hops + 1);
    }
    const buf = Buffer.from(await r.arrayBuffer()).subarray(0, MAX_BYTES);
    return {
      ok: r.ok,
      status: r.status,
      contentType: r.headers.get('content-type') || '',
      finalUrl: u.toString(),
      text: r.ok ? buf.toString('utf8') : '',
    };
  } catch (e) {
    return { ok: false, status: 0, error: e.name === 'AbortError' ? 'timed out' : 'unreachable', text: '', contentType: '' };
  } finally {
    clearTimeout(timer);
  }
}

// ---------- parsing ----------

function isHtml(file) {
  return /text\/html/i.test(file.contentType || '') || /^\s*<(!doctype html|html)\b/i.test(file.text || '');
}

// Parses robots.txt into groups. Comments stripped; consecutive User-agent
// lines share one group.
function parseRobots(text) {
  const groups = [];
  const sitemaps = [];
  let current = null;
  let lastWasRule = false;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/#.*/, '').trim();
    const idx = line.indexOf(':');
    if (!line || idx < 0) continue;
    const key = line.slice(0, idx).trim().toLowerCase();
    const val = line.slice(idx + 1).trim();
    if (key === 'sitemap') { sitemaps.push(val); continue; }
    if (key === 'user-agent') {
      if (!current || lastWasRule) {
        current = { agents: [], rules: [] };
        groups.push(current);
      }
      current.agents.push(val.toLowerCase());
      lastWasRule = false;
    } else if ((key === 'allow' || key === 'disallow') && current) {
      current.rules.push({ type: key, path: val });
      lastWasRule = true;
    }
  }
  return { groups, sitemaps };
}

// Whether a crawler may fetch the homepage. A named group for the bot wins;
// otherwise the * group applies. Blocked means "Disallow: /" with no
// "Allow: /" in the same group. "Disallow: /admin" does NOT block the root.
function rootAccess(parsed, bot) {
  const name = bot.toLowerCase();
  const named = parsed.groups.filter((g) => g.agents.includes(name));
  const wildcard = parsed.groups.filter((g) => g.agents.includes('*'));
  const use = named.length ? named : wildcard;
  if (!use.length) return { status: 'allowed', via: 'no rules' };
  const rules = use.flatMap((g) => g.rules);
  const isRoot = (p) => p === '/' || p === '/*';
  const rootDisallow = rules.some((r) => r.type === 'disallow' && isRoot(r.path));
  const rootAllow = rules.some((r) => r.type === 'allow' && isRoot(r.path));
  return {
    status: rootDisallow && !rootAllow ? 'blocked' : 'allowed',
    via: named.length ? 'named rule' : 'wildcard rule',
  };
}

function visibleText(html) {
  return html
    .replace(/<!--[\s\S]*?-->/g, ' ')
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<svg[\s\S]*?<\/svg>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/gi, ' ')
    .replace(/&amp;/gi, '&')
    .replace(/\s+/g, ' ')
    .trim();
}

function walkTypes(node, types) {
  if (Array.isArray(node)) { node.forEach((n) => walkTypes(n, types)); return; }
  if (node && typeof node === 'object') {
    const t = node['@type'];
    if (t) (Array.isArray(t) ? t : [t]).forEach((x) => typeof x === 'string' && types.add(x));
    Object.values(node).forEach((v) => walkTypes(v, types));
  }
}

function jsonLd(html) {
  const out = { blocks: 0, invalid: 0, types: new Set() };
  const re = /<script[^>]*type=["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi;
  let m;
  while ((m = re.exec(html))) {
    out.blocks++;
    try {
      walkTypes(JSON.parse(m[1].trim()), out.types);
    } catch {
      out.invalid++;
    }
  }
  return out;
}

function metaContent(html, attr, value) {
  for (const tag of html.match(/<meta\b[^>]*>/gi) || []) {
    const key = (tag.match(new RegExp(`\\b${attr}\\s*=\\s*["']([^"']+)["']`, 'i')) || [])[1];
    if (key && key.toLowerCase() === value) {
      const c = (tag.match(/\bcontent\s*=\s*["']([^"']*)["']/i) || [])[1];
      return c ? c.trim() : '';
    }
  }
  return null;
}

// ---------- analysis (pure: takes fetched files, returns the report) ----------

function analyze({ domain, home, robots, llms, sitemap }) {
  const html = home.text || '';
  const text = visibleText(html);
  const wordCount = text ? text.split(' ').filter(Boolean).length : 0;
  const checks = [];
  const add = (c) => checks.push(c);

  // Crawler access
  const robotsIsHtml = robots.ok && isHtml(robots);
  const parsed = robots.ok && !robotsIsHtml ? parseRobots(robots.text) : null;

  if (robotsIsHtml) {
    add({ id: 'robots-file', category: 'Crawler access', impact: 'high', status: 'fail',
      title: 'robots.txt returns an HTML page',
      detail: 'The URL /robots.txt returns a web page, not a robots file. Crawlers read it as having no rules.',
      fix: 'Serve robots.txt as plain text from the site root. If a rewrite catches this path, exclude it.' });
  } else if (!robots.ok) {
    add({ id: 'robots-file', category: 'Crawler access', impact: 'medium', status: 'warn',
      title: 'No robots.txt file',
      detail: 'Crawlers default to allowed, but there is no stated policy for AI crawlers.',
      fix: 'Add a robots.txt that states the AI crawler policy explicitly and links to the sitemap.' });
  } else {
    add({ id: 'robots-file', category: 'Crawler access', impact: 'medium', status: 'pass',
      title: 'robots.txt found and readable',
      detail: `${parsed.groups.length} rule group(s) found.`,
      fix: null });
  }

  const blocked = AI_BOTS.filter((b) => parsed && rootAccess(parsed, b.name).status === 'blocked');
  const blockedCritical = blocked.filter((b) => b.critical);
  const blockedOther = blocked.filter((b) => !b.critical);
  if (blockedCritical.length) {
    add({ id: 'ai-crawlers', category: 'Crawler access', impact: 'high', status: 'fail',
      title: `AI crawlers blocked: ${blockedCritical.map((b) => b.name).join(', ')}`,
      detail: 'robots.txt blocks these crawlers from the homepage. The assistants they serve cannot read the site through them.',
      fix: 'Confirm the block is intentional. If not, remove the Disallow: / rule for these user agents.' });
  } else if (blockedOther.length) {
    add({ id: 'ai-crawlers', category: 'Crawler access', impact: 'medium', status: 'warn',
      title: `Blocked: ${blockedOther.map((b) => b.name).join(', ')}`,
      detail: `Bingbot blocking also removes the site from Bing and Copilot results. Google-Extended only controls Google AI training.`,
      fix: 'Confirm each block is intentional.' });
  } else {
    add({ id: 'ai-crawlers', category: 'Crawler access', impact: 'high', status: 'pass',
      title: 'AI crawlers are not blocked from the homepage',
      detail: 'No robots.txt rule blocks the homepage for GPTBot, OAI-SearchBot, ClaudeBot, PerplexityBot, Google-Extended, or Bingbot.',
      fix: null });
  }

  const sitemapIsHtml = sitemap.ok && isHtml(sitemap);
  const sitemapValid = sitemap.ok && !sitemapIsHtml && /<(urlset|sitemapindex)\b/i.test(sitemap.text);
  const urlCount = sitemapValid ? (sitemap.text.match(/<loc>/gi) || []).length : 0;
  if (sitemapValid) {
    add({ id: 'sitemap', category: 'Crawler access', impact: 'medium', status: 'pass',
      title: 'sitemap.xml found',
      detail: `${urlCount} URL(s) listed.`,
      fix: null });
  } else {
    add({ id: 'sitemap', category: 'Crawler access', impact: 'medium', status: sitemapIsHtml ? 'fail' : 'warn',
      title: sitemapIsHtml ? 'sitemap.xml returns an HTML page' : 'No valid sitemap.xml',
      detail: 'Without a sitemap, crawlers find pages only through links.',
      fix: 'Publish a sitemap.xml at the site root and reference it in robots.txt.' });
  }
  if (parsed && sitemapValid) {
    const listed = parsed.sitemaps.length > 0;
    add({ id: 'sitemap-listed', category: 'Crawler access', impact: 'low', status: listed ? 'pass' : 'warn',
      title: listed ? 'Sitemap referenced in robots.txt' : 'Sitemap not referenced in robots.txt',
      detail: listed ? parsed.sitemaps.join(', ') : 'sitemap.xml exists but robots.txt does not point to it.',
      fix: listed ? null : 'Add a Sitemap: line to robots.txt.' });
  }

  // Renderability
  if (wordCount >= 150) {
    add({ id: 'text-in-html', category: 'Renderability', impact: 'high', status: 'pass',
      title: `Homepage text is in the HTML (${wordCount} words)`,
      detail: 'Crawlers that do not run JavaScript can read the core content.',
      fix: null });
  } else {
    add({ id: 'text-in-html', category: 'Renderability', impact: 'high', status: wordCount < 50 ? 'fail' : 'warn',
      title: `Only ${wordCount} words of homepage text in the HTML`,
      detail: 'Crawlers that do not run JavaScript see only this much. Content loaded by script is invisible to them.',
      fix: 'Render the core homepage content on the server or in static HTML.' });
  }

  // Facts on the page
  const emails = (text.match(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g) || []).length;
  const hasPhone = /(\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}/.test(text);
  const hasAddress = /[ABCEGHJ-NPRSTVXY]\d[ABCEGHJ-NPRSTV-Z][ -]?\d[ABCEGHJ-NPRSTV-Z]\d/i.test(text) ||
    /\b\d{1,5}\s+[A-Za-z0-9.' -]+\s(street|st|avenue|ave|road|rd|drive|dr|blvd|boulevard|way|suite|unit|highway|hwy)\b/i.test(text);
  add({ id: 'contact-email', category: 'Facts on the page', impact: 'high', status: emails ? 'pass' : 'fail',
    title: emails ? 'Contact email visible on the homepage' : 'No contact email visible on the homepage',
    detail: emails ? `${emails} email address(es) found.` : 'Assistants that describe a business often pull its contact details from the homepage.',
    fix: emails ? null : 'Show a contact email in visible text on the homepage.' });
  add({ id: 'contact-phone', category: 'Facts on the page', impact: 'medium', status: hasPhone ? 'pass' : 'warn',
    title: hasPhone ? 'Phone number visible on the homepage' : 'No phone number visible on the homepage',
    detail: hasPhone ? 'Found.' : 'Not found in visible text.',
    fix: hasPhone ? null : 'Add the business phone number to visible homepage text.' });
  add({ id: 'address', category: 'Facts on the page', impact: 'medium', status: hasAddress ? 'pass' : 'warn',
    title: hasAddress ? 'Postal address visible on the homepage' : 'No postal address visible on the homepage',
    detail: hasAddress ? 'Found.' : 'Local and service businesses are matched to a location through the address.',
    fix: hasAddress ? null : 'Add the business address and service area to visible homepage text.' });

  // Structured data
  const ld = jsonLd(html);
  if (ld.blocks === 0) {
    add({ id: 'jsonld-present', category: 'Structured data', impact: 'high', status: 'fail',
      title: 'No JSON-LD structured data on the homepage',
      detail: 'The homepage declares no machine-readable facts about the business.',
      fix: 'Add Organization or LocalBusiness JSON-LD that matches the visible content.' });
  } else {
    add({ id: 'jsonld-present', category: 'Structured data', impact: 'high', status: ld.invalid ? 'fail' : 'pass',
      title: ld.invalid
        ? `${ld.invalid} of ${ld.blocks} JSON-LD block(s) fail to parse`
        : `${ld.blocks} JSON-LD block(s) found`,
      detail: ld.invalid
        ? 'Parsers skip invalid blocks, so the markup is ignored.'
        : `Types declared: ${[...ld.types].join(', ') || 'none'}.`,
      fix: ld.invalid ? 'Fix the JSON syntax in the structured data block.' : null });
  }
  const orgTypes = ['Organization', 'LocalBusiness', 'ProfessionalService', 'Corporation', 'Person'];
  const hasOrg = [...ld.types].some((t) => orgTypes.includes(t) || /Business$|Service$/.test(t));
  add({ id: 'org-schema', category: 'Structured data', impact: 'high', status: hasOrg ? 'pass' : 'fail',
    title: hasOrg ? 'Organization or business schema present' : 'No Organization or LocalBusiness schema',
    detail: hasOrg ? 'Entity markup declared.' : 'The business identity is not declared in machine-readable form.',
    fix: hasOrg ? null : 'Add Organization or LocalBusiness JSON-LD with name, URL, address, and phone.' });

  const faqHeadings = (html.match(/<h[23]\b[^>]*>[\s\S]*?<\/h[23]>/gi) || [])
    .map((h) => visibleText(h)).filter((h) => /faq|frequently asked|common questions/i.test(h));
  const hasFaqSchema = ld.types.has('FAQPage');
  add({ id: 'faq', category: 'Structured data', impact: 'high', status: hasFaqSchema ? 'pass' : 'warn',
    title: hasFaqSchema ? 'FAQPage markup present'
      : faqHeadings.length ? 'FAQ section visible but not marked up'
      : 'No FAQ section on the homepage',
    detail: hasFaqSchema ? 'FAQ questions and answers are declared.'
      : faqHeadings.length ? 'Visible FAQ heading found without FAQPage markup.'
      : 'Questions a buyer asks, answered in visible text, are the usual source of direct answers.',
    fix: hasFaqSchema ? null
      : faqHeadings.length ? 'Add FAQPage JSON-LD that mirrors the visible questions and answers exactly.'
      : 'Add a visible FAQ of real customer questions, then mark it up with FAQPage JSON-LD.' });

  // Facts on the page: on-page basics
  const title = (html.match(/<title[^>]*>([\s\S]*?)<\/title>/i) || [])[1];
  const titleLen = title ? visibleText(title).length : 0;
  add({ id: 'title', category: 'On-page basics', impact: 'medium',
    status: !title ? 'fail' : titleLen >= 30 && titleLen <= 60 ? 'pass' : 'warn',
    title: !title ? 'No <title> tag' : `Title is ${titleLen} characters`,
    detail: 'Recommended length is 30 to 60 characters.',
    fix: !title ? 'Add a title tag.' : titleLen >= 30 && titleLen <= 60 ? null : 'Rewrite the title to 30 to 60 characters.' });

  const desc = metaContent(html, 'name', 'description');
  const descLen = desc ? desc.length : 0;
  add({ id: 'meta-description', category: 'On-page basics', impact: 'medium',
    status: !desc ? 'fail' : descLen >= 70 && descLen <= 160 ? 'pass' : 'warn',
    title: !desc ? 'No meta description' : `Meta description is ${descLen} characters`,
    detail: 'Recommended length is 70 to 160 characters.',
    fix: !desc ? 'Add a meta description that states what the business does.' : descLen >= 70 && descLen <= 160 ? null : 'Rewrite to 70 to 160 characters.' });

  const h1Count = (html.match(/<h1\b/gi) || []).length;
  add({ id: 'h1', category: 'On-page basics', impact: 'medium',
    status: h1Count === 1 ? 'pass' : 'warn',
    title: h1Count === 1 ? 'One H1 on the homepage' : `${h1Count} H1 tags on the homepage`,
    detail: 'One H1 states the main topic of the page.',
    fix: h1Count === 1 ? null : 'Keep one H1 and use H2 for section headings.' });

  add({ id: 'lang', category: 'On-page basics', impact: 'low', status: /<html\b[^>]*\blang\s*=/i.test(html) ? 'pass' : 'warn',
    title: /<html\b[^>]*\blang\s*=/i.test(html) ? 'Language declared' : 'No lang attribute on <html>',
    detail: 'Declares the page language to crawlers and screen readers.', fix: /<html\b[^>]*\blang\s*=/i.test(html) ? null : 'Add lang="en" (or the correct code) to the html tag.' });

  const hasCanonical = /<link\b[^>]*rel\s*=\s*["']canonical["']/i.test(html);
  add({ id: 'canonical', category: 'On-page basics', impact: 'low', status: hasCanonical ? 'pass' : 'warn',
    title: hasCanonical ? 'Canonical URL declared' : 'No canonical URL declared',
    detail: 'Tells crawlers which URL is the authoritative version of the page.',
    fix: hasCanonical ? null : 'Add a rel="canonical" link to the homepage.' });

  add({ id: 'viewport', category: 'On-page basics', impact: 'medium', status: metaContent(html, 'name', 'viewport') ? 'pass' : 'fail',
    title: metaContent(html, 'name', 'viewport') ? 'Viewport meta tag present' : 'No viewport meta tag',
    detail: 'Required for the page to render correctly on mobile.',
    fix: metaContent(html, 'name', 'viewport') ? null : 'Add <meta name="viewport" content="width=device-width, initial-scale=1">.' });

  const imgs = html.match(/<img\b[^>]*>/gi) || [];
  const noAlt = imgs.filter((t) => !/\balt\s*=/i.test(t)).length;
  add({ id: 'img-alt', category: 'On-page basics', impact: 'low', status: noAlt ? 'warn' : 'pass',
    title: noAlt ? `${noAlt} of ${imgs.length} image(s) have no alt attribute` : 'All images have alt attributes',
    detail: 'Alt text describes images to crawlers and screen readers.',
    fix: noAlt ? 'Add descriptive alt text to each image.' : null });

  // AI-readable files
  if (isHtml(llms)) {
    add({ id: 'llms-file', category: 'AI-readable files', impact: 'high', status: 'fail',
      title: 'llms.txt returns an HTML page',
      detail: 'The URL /llms.txt serves a web page, not the file. AI tools reading it get no business description.',
      fix: 'Serve llms.txt as plain text from the site root. If a rewrite catches this path, exclude it.' });
  } else if (!llms.ok) {
    add({ id: 'llms-file', category: 'AI-readable files', impact: 'medium', status: 'warn',
      title: 'No llms.txt file',
      detail: 'llms.txt is a plain-text summary of the business for AI tools. It is not yet a standard that all assistants read.',
      fix: 'Publish an llms.txt at the site root with a title, summary, and key facts.' });
  } else if (!/^#\s/m.test(llms.text.trim().slice(0, 200))) {
    add({ id: 'llms-file', category: 'AI-readable files', impact: 'medium', status: 'warn',
      title: 'llms.txt has no title line',
      detail: 'The file should start with a # title, then a summary.',
      fix: 'Start the file with "# Business name" and a one-line summary.' });
  } else {
    const hasSummary = /^>\s/m.test(llms.text);
    add({ id: 'llms-file', category: 'AI-readable files', impact: 'medium', status: hasSummary ? 'pass' : 'warn',
      title: hasSummary ? 'llms.txt found with a summary' : 'llms.txt found but has no summary line',
      detail: 'Served as plain text.',
      fix: hasSummary ? null : 'Add a "> " summary line under the title.' });
  }

  // Build the report
  const categories = CATEGORY_ORDER.map((name) => ({
    name,
    checks: checks.filter((c) => c.category === name).map(({ category, ...rest }) => rest),
  })).filter((c) => c.checks.length);

  const sevRank = { fail: 0, warn: 1, pass: 2 };
  const impactRank = { high: 0, medium: 1, low: 2 };
  const catRank = (cat) => CATEGORY_ORDER.indexOf(cat);
  const fixFirst = checks
    .filter((c) => c.status !== 'pass')
    .sort((a, b) => sevRank[a.status] - sevRank[b.status] ||
      impactRank[a.impact] - impactRank[b.impact] ||
      catRank(a.category) - catRank(b.category))
    .slice(0, 5)
    .map((c) => ({ id: c.id, title: c.title, fix: c.fix }));

  return {
    domain,
    scannedAt: new Date().toISOString(),
    pagesChecked: [
      { url: `https://${domain}/`, ok: home.ok, status: home.status },
      { url: `https://${domain}/robots.txt`, ok: robots.ok && !robotsIsHtml, status: robots.status },
      { url: `https://${domain}/sitemap.xml`, ok: sitemapValid, status: sitemap.status },
      { url: `https://${domain}/llms.txt`, ok: llms.ok && !isHtml(llms), status: llms.status },
    ],
    checksPassed: checks.filter((c) => c.status === 'pass').length,
    checksTotal: checks.length,
    fixFirst,
    categories,
    notChecked: NOT_CHECKED,
  };
}

// ---------- handler ----------

const hits = new Map();
function rateLimited(ip) {
  const now = Date.now();
  const recent = (hits.get(ip) || []).filter((t) => now - t < 3600_000);
  if (recent.length >= 10) return true;
  recent.push(now);
  hits.set(ip, recent);
  return false;
}

async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Use POST.' });

  const ip = String(req.headers['x-forwarded-for'] || req.socket?.remoteAddress || 'unknown').split(',')[0].trim();
  if (rateLimited(ip)) return res.status(429).json({ error: 'Too many scans from this address. Try again later.' });

  let body = req.body;
  if (typeof body === 'string') { try { body = JSON.parse(body); } catch { body = {}; } }
  const domain = cleanDomain(body && body.domain);
  if (!domain) return res.status(400).json({ error: 'Enter a valid website domain, such as example.com.' });

  const base = `https://${domain}`;
  const [home, robots, llms, sitemap] = await Promise.all([
    getFile(`${base}/`),
    getFile(`${base}/robots.txt`),
    getFile(`${base}/llms.txt`),
    getFile(`${base}/sitemap.xml`),
  ]);

  if (!home.ok) {
    const reason = home.error || `HTTP ${home.status}`;
    return res.status(422).json({ error: `We couldn't load ${domain} (${reason}). Check the address and try again.` });
  }

  return res.status(200).json(analyze({ domain, home, robots, llms, sitemap }));
}

module.exports = handler;
module.exports.analyze = analyze;
module.exports.parseRobots = parseRobots;
module.exports.rootAccess = rootAccess;
module.exports.cleanDomain = cleanDomain;
