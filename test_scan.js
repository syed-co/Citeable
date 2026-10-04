const assert = require('assert');
const { analyze, parseRobots, rootAccess, cleanDomain } = require('./api/scan.js');

const ok = (text, contentType = 'text/plain') => ({ ok: true, status: 200, contentType, text });
const miss = { ok: false, status: 404, contentType: '', text: '' };
const htmlFile = { ok: true, status: 200, contentType: 'text/html; charset=utf-8', text: '<!doctype html><html><body>hi</body></html>' };

const longText = Array.from({ length: 200 }, (_, i) => `word${i}`).join(' ');
const goodHtml = `<!doctype html><html lang="en"><head>
<title>Citeable: AI Search Visibility for Local Businesses</title>
<meta name="description" content="Citeable audits and fixes how ChatGPT, Perplexity and Google AI describe Canadian businesses, with measured on-site fixes.">
<link rel="canonical" href="https://example.ca/">
<meta name="viewport" content="width=device-width, initial-scale=1">
<script type="application/ld+json">{"@context":"https://schema.org","@graph":[{"@type":"Organization","name":"Example"},{"@type":"WebSite"}]}</script>
<script type="application/ld+json">{"@type":"FAQPage","mainEntity":[]}</script>
</head><body><h1>Example Co</h1><h2>FAQ</h2><img src="a.png" alt="logo">
<p>${longText}</p><p>Email hello@example.ca or call 604-555-0100. 123 Main Street, Surrey BC V3T 1A1</p></body></html>`;

const goodRobots = ok('User-agent: *\nAllow: /\nSitemap: https://example.ca/sitemap.xml\n');
const goodSitemap = ok('<?xml version="1.0"?><urlset><url><loc>https://example.ca/</loc></url><url><loc>https://example.ca/a</loc></url></urlset>', 'application/xml');
const goodLlms = ok('# Example Co\n\n> Canadian AEO service for local businesses.\n\n## Facts\n- Surrey, BC\n');

const find = (r, id) => r.categories.flatMap((c) => c.checks).find((c) => c.id === id);

// 1. healthy site: no false failures on the key checks
{
  const r = analyze({ domain: 'example.ca', home: ok(goodHtml, 'text/html'), robots: goodRobots, llms: goodLlms, sitemap: goodSitemap });
  for (const id of ['ai-crawlers', 'sitemap', 'text-in-html', 'contact-email', 'contact-phone', 'address', 'jsonld-present', 'org-schema', 'faq', 'title', 'meta-description', 'h1', 'llms-file', 'viewport']) {
    assert.strictEqual(find(r, id).status, 'pass', `healthy site: ${id} should pass, got ${find(r, id).status} (${find(r, id).title})`);
  }
  assert.strictEqual(r.fixFirst.length, 0, 'fully healthy fixture should have no fixes');
  console.log('PASS healthy site; checksPassed', r.checksPassed, '/', r.checksTotal, '| remaining:', r.fixFirst.map(f => f.title));
}

// 2. GPTBot blocked, wildcard only disallows /admin -> ClaudeBot must NOT be flagged
{
  const robots = ok('User-agent: GPTBot\nDisallow: /\n\nUser-agent: *\nDisallow: /admin\n');
  const r = analyze({ domain: 'example.ca', home: ok(goodHtml, 'text/html'), robots, llms: goodLlms, sitemap: goodSitemap });
  const c = find(r, 'ai-crawlers');
  assert.strictEqual(c.status, 'fail');
  assert.ok(c.title.includes('GPTBot') && !c.title.includes('ClaudeBot'), 'only GPTBot should be named: ' + c.title);
  console.log('PASS block detection:', c.title);
}

// 3. llms.txt served as HTML (rewrite catch-all) -> fail, not pass
{
  const r = analyze({ domain: 'example.ca', home: ok(goodHtml, 'text/html'), robots: goodRobots, llms: htmlFile, sitemap: goodSitemap });
  assert.strictEqual(find(r, 'llms-file').status, 'fail');
  console.log('PASS llms served as HTML is flagged:', find(r, 'llms-file').title);
}

// 4. robots.txt served as HTML -> not treated as a rule set (no false "no blocks")
{
  const r = analyze({ domain: 'example.ca', home: ok(goodHtml, 'text/html'), robots: htmlFile, llms: goodLlms, sitemap: goodSitemap });
  assert.strictEqual(find(r, 'robots-file').status, 'fail');
  assert.strictEqual(find(r, 'ai-crawlers').status, 'pass', 'with HTML robots there are no parsed rules, so no blocks found');
  console.log('PASS robots-as-HTML flagged');
}

// 5. near-empty SPA shell with no schema, no contact, no meta
{
  const spa = '<!doctype html><html><head><title>App</title></head><body><div id="root"></div><script src="/app.js"></script></body></html>';
  const r = analyze({ domain: 'spa.ca', home: ok(spa, 'text/html'), robots: miss, llms: miss, sitemap: miss });
  assert.strictEqual(find(r, 'text-in-html').status, 'fail');
  assert.strictEqual(find(r, 'jsonld-present').status, 'fail');
  assert.strictEqual(find(r, 'contact-email').status, 'fail');
  assert.strictEqual(find(r, 'llms-file').status, 'warn');
  assert.ok(r.fixFirst.length === 5, 'fix-first list capped at 5');
  console.log('PASS SPA shell: fix-first =', r.fixFirst.map(f => f.id));
}

// 6. invalid JSON-LD is reported, not silently passed
{
  const bad = goodHtml.replace('{"@type":"FAQPage","mainEntity":[]}', '{"@type":FAQPage,}');
  const r = analyze({ domain: 'example.ca', home: ok(bad, 'text/html'), robots: goodRobots, llms: goodLlms, sitemap: goodSitemap });
  assert.strictEqual(find(r, 'jsonld-present').status, 'fail');
  console.log('PASS invalid JSON-LD flagged:', find(r, 'jsonld-present').title);
}

// 7. rootAccess edge cases
{
  const p = parseRobots('User-agent: GPTBot\nUser-agent: ClaudeBot\nDisallow: /\n\nUser-agent: GPTBot\nAllow: /\n');
  assert.strictEqual(rootAccess(p, 'ClaudeBot').status, 'blocked');
  assert.strictEqual(rootAccess(p, 'GPTBot').status, 'allowed', 'Allow: / in the GPTBot group overrides');
  const q = parseRobots('User-agent: *\nDisallow: /\nAllow: /\n');
  assert.strictEqual(rootAccess(q, 'PerplexityBot').status, 'allowed');
  const comments = parseRobots('# note: Disallow: /\nUser-agent: *\nDisallow:\n');
  assert.strictEqual(rootAccess(comments, 'GPTBot').status, 'allowed', 'commented and empty Disallow must not block');
  console.log('PASS rootAccess edge cases');
}

// 8. domain cleaning
{
  assert.strictEqual(cleanDomain('https://www.Example.ca/path?x=1'), 'example.ca');
  assert.strictEqual(cleanDomain('localhost'), null);
  assert.strictEqual(cleanDomain('127.0.0.1'), null);
  assert.strictEqual(cleanDomain('a b.com'), null);
  console.log('PASS domain cleaning');
}
console.log('\nALL TESTS PASSED');
