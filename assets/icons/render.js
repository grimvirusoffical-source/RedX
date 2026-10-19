const { chromium } = require(process.env.PLAYWRIGHT_CORE || 'playwright-core');
const fs = require('fs');
(async () => {
  const [,, svgPath, out, size, bg] = process.argv;
  const svg = fs.readFileSync(svgPath, 'utf8');
  const b = await chromium.launch({ executablePath: process.env.CHROME || '/usr/bin/google-chrome', args: ['--no-sandbox'] });
  const p = await b.newPage({ viewport: { width: +size, height: +size }, deviceScaleFactor: 1 });
  await p.setContent(`<html><body style="margin:0;background:${bg||'transparent'}">${svg.replace('<svg ', `<svg width="${size}" height="${size}" `)}</body></html>`);
  await p.screenshot({ path: out, omitBackground: !bg || bg==='transparent' });
  await b.close();
})();
