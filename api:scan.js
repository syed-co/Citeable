// Citeable — Real AEO Audit API
// Deployed as a Vercel serverless function at /api/scan
// Accepts: POST { domain: "example.com" }
// Returns: { score, sections, domain, meta }

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  let { domain } = req.body || {};
  if (!domain) return res.status(400).json({ error: 'Domain required' });

  // Clean domain
  domain = domain.replace(/^https?:\/\//i, '').replace(/^www\./i, '').split('/')[0].split('?')[0].replace(/,/g, '.').toLowerCase().trim();
  if (!domain || !domain.includes('.')) return res.status(400).json({ error: 'Invalid domain' });

  const baseUrl = `https://${domain}`;
  const results = { domain, checks: {}, raw: {} };

  // ── FETCH HELPERS ──────────────────────────────────────────────────────────
  const fetchWithTimeout = async (url, ms = 8000) => {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), ms);
    try {
      const r = await fetch(url, {
        signal: ctrl.signal,
        headers: { 'User-Agent': 'CiteableBot/1.0 (+https://citeable.com)' },
        redirect: 'follow'
      });
      clearTimeout(timer);
      return r;
    } catch (e) {
      clearTimeout(timer);
      return null;
    }
  };

  const fetchText = async (url) => {
    const r = await fetchWithTimeout(url);
    if (!r || !r.ok) return null;
    try { return await r.text(); } catch { return null; }
  };

  // ── PARALLEL FETCHES ───────────────────────────────────────────────────────
  const [homeHtml, robotsTxt, llmsTxt, sitemapXml] = await Promise.all([
    fetchText(baseUrl),
    fetchText(`${baseUrl}/robots.txt`),
    fetchText(`${baseUrl}/llms.txt`),
    fetchText(`${baseUrl}/sitemap.xml`),
  ]);

  results.raw = {
    hasHome: !!homeHtml,
    homeLength: homeHtml?.length || 0,
    hasRobots: !!robotsTxt,
    hasLlms: !!llmsTxt,
    hasSitemap: !!sitemapXml,
  };

  // ── CHECK FUNCTIONS ────────────────────────────────────────────────────────

  // 1. Schema markup
  const schemaMatches = homeHtml ? [...homeHtml.matchAll(/"@type"\s*:\s*"([^"]+)"/g)].map(m => m[1]) : [];
  const hasOrgSchema = schemaMatches.some(t => ['Organization','LocalBusiness','ProfessionalService','MedicalOrganization','LegalService','AccountingService'].includes(t));
  const hasFaqSchema = schemaMatches.some(t => t === 'FAQPage' || t === 'Question');
  const hasWebsiteSchema = schemaMatches.some(t => t === 'WebSite' || t === 'WebPage');
  const hasBreadcrumb = schemaMatches.some(t => t === 'BreadcrumbList');
  const hasArticleSchema = schemaMatches.some(t => ['Article','BlogPosting','NewsArticle'].includes(t));
  const schemaTypes = [...new Set(schemaMatches)];

  // 2. Meta tags
  const title = homeHtml?.match(/<title[^>]*>([^<]+)<\/title>/i)?.[1]?.trim() || null;
  const metaDesc = homeHtml?.match(/<meta[^>]+name=["']description["'][^>]+content=["']([^"']+)["']/i)?.[1]?.trim() || null;
  const ogTitle = homeHtml?.match(/<meta[^>]+property=["']og:title["'][^>]+content=["']([^"']+)["']/i)?.[1]?.trim() || null;
  const ogDesc = homeHtml?.match(/<meta[^>]+property=["']og:description["'][^>]+content=["']([^"']+)["']/i)?.[1]?.trim() || null;
  const canonical = homeHtml?.match(/<link[^>]+rel=["']canonical["'][^>]+href=["']([^"']+)["']/i)?.[1]?.trim() || null;

  // 3. Heading structure
  const h1s = homeHtml ? [...homeHtml.matchAll(/<h1[^>]*>([\s\S]*?)<\/h1>/gi)].map(m => m[1].replace(/<[^>]+>/g,'').trim()) : [];
  const h2s = homeHtml ? [...homeHtml.matchAll(/<h2[^>]*>([\s\S]*?)<\/h2>/gi)].map(m => m[1].replace(/<[^>]+>/g,'').trim()) : [];
  const h3s = homeHtml ? [...homeHtml.matchAll(/<h3[^>]*>([\s\S]*?)<\/h3>/gi)].map(m => m[1].replace(/<[^>]+>/g,'').trim()) : [];

  // 4. FAQ detection (look for FAQ patterns in headings and content)
  const faqPatterns = /\b(faq|frequently asked|common questions?|questions? (and|&) answers?|q\s*(&|and)\s*a)\b/i;
  const hasFaqHeading = [...h2s, ...h3s].some(h => faqPatterns.test(h));
  const hasFaqContent = homeHtml ? faqPatterns.test(homeHtml.substring(0, 50000)) : false;

  // 5. AI bot access in robots.txt
  const gptBotBlocked = robotsTxt ? /Disallow:\s*\//.test(robotsTxt.replace(/[\s\S]*?User-agent:\s*GPTBot/i, '').split(/User-agent:/i)[0] || '') : false;
  const gptBotMentioned = robotsTxt ? /GPTBot/i.test(robotsTxt) : false;
  const claudeBotMentioned = robotsTxt ? /ClaudeBot|anthropic/i.test(robotsTxt) : false;
  const bingBotMentioned = robotsTxt ? /bingbot/i.test(robotsTxt) : false;

  // More precise: check if GPTBot is explicitly disallowed
  let gptBotDisallowed = false;
  let claudeBotDisallowed = false;
  if (robotsTxt) {
    const sections = robotsTxt.split(/(?=User-agent:)/gi);
    for (const section of sections) {
      if (/User-agent:\s*(GPTBot|\*)/i.test(section)) {
        if (/Disallow:\s*\//m.test(section)) gptBotDisallowed = true;
      }
      if (/User-agent:\s*(ClaudeBot|anthropic|\*)/i.test(section)) {
        if (/Disallow:\s*\//m.test(section)) claudeBotDisallowed = true;
      }
    }
  }

  // 6. Content signals
  const wordCount = homeHtml ? homeHtml.replace(/<[^>]+>/g,' ').replace(/\s+/g,' ').trim().split(' ').length : 0;
  const hasAboutSection = homeHtml ? /\babout\b/i.test(homeHtml.substring(0,50000)) : false;
  const hasContactInfo = homeHtml ? (/\b[\w.+-]+@[\w-]+\.\w{2,}\b/.test(homeHtml) || /\b(\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b/.test(homeHtml)) : false;
  const hasAddress = homeHtml ? /\b(street|avenue|drive|road|blvd|suite|floor|unit)\b/i.test(homeHtml) : false;

  // 7. llms.txt
  const llmsHasContent = llmsTxt && llmsTxt.length > 50;

  // 8. Sitemap
  const sitemapPageCount = sitemapXml ? (sitemapXml.match(/<url>/g) || []).length : 0;

  // 9. Title/desc length checks
  const titleLength = title?.length || 0;
  const descLength = metaDesc?.length || 0;
  const titleOptimal = titleLength >= 30 && titleLength <= 65;
  const descOptimal = descLength >= 120 && descLength <= 160;

  // ── SCORE EACH SECTION ────────────────────────────────────────────────────

  const sections = [];
  let totalScore = 0;

  // SECTION 1: Schema & Structured Data (25 pts)
  let schemaScore = 0;
  const schemaChecks = [];

  if (hasOrgSchema) {
    schemaScore += 10;
    schemaChecks.push({ status: 'green', text: `Organization or LocalBusiness schema detected — AI engines can identify ${domain} as a real, classifiable entity` });
  } else {
    schemaChecks.push({ status: 'red', text: `No Organization or LocalBusiness schema found — AI engines cannot formally classify what ${domain} does or who it serves` });
  }

  if (hasFaqSchema) {
    schemaScore += 10;
    schemaChecks.push({ status: 'green', text: 'FAQPage schema implemented — this is the highest-impact single signal for getting cited in AI answers' });
  } else {
    schemaChecks.push({ status: 'red', text: 'No FAQPage schema detected — this is the single highest-impact fix available for AI citation; questions and answers marked up with schema are fed directly into AI engines' });
  }

  if (hasWebsiteSchema) {
    schemaScore += 3;
    schemaChecks.push({ status: 'green', text: 'WebSite schema present — supports sitelinks and search actions in AI-enhanced results' });
  }

  if (schemaTypes.length > 2) {
    schemaScore += 2;
    schemaChecks.push({ status: 'green', text: `${schemaTypes.length} schema types detected (${schemaTypes.slice(0,3).join(', ')}${schemaTypes.length > 3 ? '…' : ''}) — rich markup improves AI comprehension` });
  } else if (schemaTypes.length === 0) {
    schemaChecks.push({ status: 'red', text: `No structured data found on ${domain} — the page is invisible to AI engines that rely on machine-readable signals` });
  } else {
    schemaChecks.push({ status: 'amber', text: `Only ${schemaTypes.length} schema type(s) found — more coverage across page types would significantly improve AI comprehension` });
  }

  const schemaRating = schemaScore >= 18 ? 'Good' : schemaScore >= 8 ? 'Fair' : 'Poor';
  sections.push({ title: 'Schema & Structured Data', rating: schemaRating, score: schemaScore, max: 25, checks: schemaChecks.slice(0, 3) });
  totalScore += schemaScore;

  // SECTION 2: Content Structure for AI (25 pts)
  let contentScore = 0;
  const contentChecks = [];

  if (h1s.length === 1) {
    contentScore += 5;
    contentChecks.push({ status: 'green', text: `Single clear H1 found: "${h1s[0].substring(0,60)}${h1s[0].length>60?'…':''}" — correct heading structure aids AI extraction` });
  } else if (h1s.length === 0) {
    contentChecks.push({ status: 'red', text: 'No H1 heading detected — AI engines use the primary heading to understand page topic and context' });
  } else {
    contentChecks.push({ status: 'amber', text: `${h1s.length} H1 headings found — multiple H1s confuse AI engines about the page's primary topic` });
  }

  if (h2s.length >= 3) {
    contentScore += 5;
    contentChecks.push({ status: 'green', text: `${h2s.length} H2 subheadings found — well-structured content is easier for AI engines to extract and cite` });
  } else if (h2s.length > 0) {
    contentScore += 2;
    contentChecks.push({ status: 'amber', text: `Only ${h2s.length} H2 subheading(s) — more structured sections with descriptive headings would help AI engines parse your content` });
  } else {
    contentChecks.push({ status: 'red', text: 'No H2 subheadings detected — flat content structure makes it very difficult for AI to extract specific answers' });
  }

  if (hasFaqHeading || hasFaqContent) {
    contentScore += 10;
    contentChecks.push({ status: 'green', text: 'FAQ content detected on the page — question-and-answer format is the format AI engines most readily cite' });
  } else {
    contentChecks.push({ status: 'red', text: `No FAQ section found on ${domain} — adding a Q&A section with your most-asked questions is the fastest path to AI citations` });
  }

  if (metaDesc && descOptimal) {
    contentScore += 5;
    contentChecks.push({ status: 'green', text: `Meta description is ${descLength} characters — well within the optimal range for AI summary extraction` });
  } else if (metaDesc) {
    contentScore += 2;
    contentChecks.push({ status: 'amber', text: `Meta description is ${descLength} characters — ${descLength < 120 ? 'too short, expand to 120-160 characters' : 'too long, trim to under 160 characters'} for optimal AI extraction` });
  } else {
    contentChecks.push({ status: 'red', text: 'No meta description found — AI engines frequently use this as a direct source for brand summaries and introductions' });
  }

  const contentRating = contentScore >= 20 ? 'Good' : contentScore >= 10 ? 'Fair' : 'Poor';
  sections.push({ title: 'Content Structure for AI', rating: contentRating, score: contentScore, max: 25, checks: contentChecks.slice(0, 3) });
  totalScore += contentScore;

  // SECTION 3: Technical AI Accessibility (20 pts)
  let techScore = 0;
  const techChecks = [];

  if (!robotsTxt) {
    techScore += 3;
    techChecks.push({ status: 'amber', text: `No robots.txt found at ${domain}/robots.txt — while not blocking AI crawlers, it's best practice to explicitly allow GPTBot and ClaudeBot` });
  } else if (gptBotDisallowed) {
    techChecks.push({ status: 'red', text: `GPTBot is blocked in robots.txt — ChatGPT cannot crawl or index ${domain}, directly preventing AI citations` });
  } else if (gptBotMentioned) {
    techScore += 8;
    techChecks.push({ status: 'green', text: `GPTBot is explicitly addressed in robots.txt — ${domain} is configured for AI crawler access` });
  } else {
    techScore += 4;
    techChecks.push({ status: 'amber', text: `robots.txt exists but does not explicitly address GPTBot or ClaudeBot — add explicit Allow rules to signal AI crawler welcome` });
  }

  if (claudeBotDisallowed) {
    techChecks.push({ status: 'red', text: `ClaudeBot (Anthropic) is blocked in robots.txt — prevents indexing by Claude-powered AI systems` });
  } else if (claudeBotMentioned) {
    techScore += 4;
    techChecks.push({ status: 'green', text: 'ClaudeBot access explicitly configured in robots.txt' });
  }

  if (llmsHasContent) {
    techScore += 8;
    techChecks.push({ status: 'green', text: `llms.txt found and populated at ${domain}/llms.txt — this file directly guides AI crawlers on how to understand your content, very few businesses have this` });
  } else if (llmsTxt !== null) {
    techScore += 2;
    techChecks.push({ status: 'amber', text: `llms.txt exists at ${domain}/llms.txt but appears empty — populate it with structured guidance for AI crawlers` });
  } else {
    techChecks.push({ status: 'red', text: `No llms.txt file found — this emerging standard lets you directly tell AI engines what your business does and how to cite you; almost no businesses have it yet` });
  }

  if (hasSitemap) {
    techScore += 4;
    const pageNote = sitemapPageCount > 0 ? ` (${sitemapPageCount} pages indexed)` : '';
    techChecks.push({ status: 'green', text: `XML sitemap found${pageNote} — helps AI crawlers discover and index all your content` });
  } else {
    techChecks.push({ status: 'amber', text: `No XML sitemap found at ${domain}/sitemap.xml — a sitemap helps AI crawlers systematically discover your full content` });
  }

  const techRating = techScore >= 16 ? 'Good' : techScore >= 8 ? 'Fair' : 'Poor';
  sections.push({ title: 'Technical AI Accessibility', rating: techRating, score: techScore, max: 20, checks: techChecks.slice(0, 3) });
  totalScore += techScore;

  // SECTION 4: Third-Party Source Signals (15 pts)
  let sourceScore = 0;
  const sourceChecks = [];

  if (hasContactInfo) {
    sourceScore += 5;
    sourceChecks.push({ status: 'green', text: `Contact information (email or phone) found on ${domain} — consistent NAP data across your site and directories strengthens AI entity recognition` });
  } else {
    sourceChecks.push({ status: 'amber', text: `No contact information detected on the homepage of ${domain} — AI engines use contact data to verify business legitimacy and match to third-party directory listings` });
  }

  if (hasAddress) {
    sourceScore += 5;
    sourceChecks.push({ status: 'green', text: 'Physical address detected — local businesses with consistent address data across directories are more frequently cited for location-based queries' });
  } else {
    sourceChecks.push({ status: 'amber', text: `No address detected on ${domain} — if you serve a local market, adding your address and ensuring it matches Google Business Profile and directories improves AI citation for local queries` });
  }

  // Always flag Wikipedia/Wikidata as a gap since we can't check without backend
  sourceChecks.push({ status: 'amber', text: `Wikipedia and Wikidata entity presence could not be verified — these are among the highest-trust sources AI engines cite; a Wikidata entry for ${domain} would significantly boost authority` });

  sourceChecks.push({ status: 'amber', text: 'Review site presence (Google, Clutch, Yelp, industry directories) requires manual verification — AI engines heavily weight third-party citations from high-authority review platforms' });

  const sourceRating = sourceScore >= 12 ? 'Good' : sourceScore >= 6 ? 'Fair' : 'Poor';
  sections.push({ title: 'Third-Party Source Signals', rating: sourceRating, score: sourceScore, max: 15, checks: sourceChecks.slice(0, 3) });
  totalScore += sourceScore;

  // SECTION 5: AI Citation Coverage (15 pts)
  let citationScore = 0;
  const citationChecks = [];

  // We can check if domain appears on some public indexes — but realistically
  // we flag this as requiring manual audit and explain why
  citationChecks.push({ status: 'amber', text: `Whether ${domain} appears in ChatGPT, Perplexity, and Gemini responses requires a live query audit — AI citations are not publicly indexed and vary by question phrasing, geography, and model version` });

  if (hasFaqSchema && hasOrgSchema) {
    citationScore += 8;
    citationChecks.push({ status: 'green', text: `Schema markup on ${domain} suggests AI engines have the structured data needed to cite you — but citation frequency depends on content authority and third-party signals` });
  } else if (hasFaqSchema || hasOrgSchema) {
    citationScore += 4;
    citationChecks.push({ status: 'amber', text: `Partial schema coverage gives ${domain} some AI visibility signals, but gaps in structured data likely limit how often and accurately AI engines cite the business` });
  } else {
    citationChecks.push({ status: 'red', text: `Without schema markup, ${domain} gives AI engines no structured signals to cite — competitors with FAQ and Organization schema will consistently appear instead` });
  }

  citationChecks.push({ status: 'amber', text: 'A full citation audit — running your brand name and category queries through ChatGPT, Perplexity, Gemini, and Google AI Overviews — is included in The Audit. This is where we find exactly what AI says about you today.' });

  const citationRating = citationScore >= 12 ? 'Good' : citationScore >= 5 ? 'Fair' : 'Poor';
  sections.push({ title: 'AI Citation Coverage', rating: citationRating, score: citationScore, max: 15, checks: citationChecks.slice(0, 3) });
  totalScore += citationScore;

  // ── FINAL SCORE (cap at 100) ───────────────────────────────────────────────
  const score = Math.min(100, Math.round(totalScore));

  // ── TOP OPPORTUNITIES (for email) ─────────────────────────────────────────
  const opportunities = [];
  if (!hasFaqSchema) opportunities.push('Add FAQPage schema — the single highest-impact AEO fix');
  if (!hasOrgSchema) opportunities.push('Add Organization/LocalBusiness schema markup');
  if (!llmsHasContent) opportunities.push('Create an llms.txt file to guide AI crawlers');
  if (gptBotDisallowed) opportunities.push('URGENT: Unblock GPTBot in robots.txt — ChatGPT cannot crawl your site');
  if (!hasFaqHeading && !hasFaqContent) opportunities.push('Add a FAQ section with your most-asked questions');
  if (!metaDesc) opportunities.push('Write a meta description for your homepage');
  if (!hasSitemap) opportunities.push('Create and submit an XML sitemap');

  res.status(200).json({
    domain,
    score,
    sections,
    opportunities: opportunities.slice(0, 5),
    meta: {
      title,
      metaDesc,
      schemaTypes,
      h1Count: h1s.length,
      h2Count: h2s.length,
      hasFaqSchema,
      hasOrgSchema,
      hasLlmsTxt: llmsHasContent,
      robotsTxtFound: !!robotsTxt,
      gptBotDisallowed,
      sitemapPageCount,
    }
  });
}
