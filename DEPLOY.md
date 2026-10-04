# Deploying the real scanner

Files (repo root = syed-co/Citeable):
- citeable.html   the landing page, now calling /api/scan
- api/scan.js     the audit endpoint (Vercel serverless function)
- vercel.json     catch-all rewrite to citeable.html
- llms.txt        served from the root as plain text. Operator is Syed Co.
- test_scan.js    fixture tests for the analysis. Run: node test_scan.js

Before going live, check the following:
1. curl -I https://<domain>/llms.txt returns content-type text/plain, not text/html.
2. curl -X POST https://<domain>/api/scan -H "Content-Type: application/json" -d '{"domain":"example.com"}' returns JSON, not the HTML page.
3. Scan a real site you know and read its findings against what you can see by hand.
4. Scan a bad input (for example, "localhost") and confirm the message is shown.

Known limits: the rate limit is per serverless instance, so it is best-effort. Only the homepage and three crawler files are read.
