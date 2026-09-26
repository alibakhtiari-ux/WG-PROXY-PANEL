// اسکرین‌شات‌های README از پنلِ دمو — screenshots.py این را صدا می‌زند.
//
//   node demo/screenshots.mjs <base-url> <out-dir> <share-token>
//
// Playwright لازم دارد (npm install playwright؛ یا نصبِ سراسری). مرورگرِ
// Chromium ِ خودِ Playwright کافی است؛ به فونتِ سیستمی نیازی نیست، چون پنل
// وزیرمتن را درونِ خودش دارد.
import { createRequire } from 'node:module';
import { execSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';

const require = createRequire(import.meta.url);
function loadPlaywright() {
  try { return require('playwright'); } catch (e) { /* نصبِ محلی نیست */ }
  const root = execSync('npm root -g').toString().trim();
  return require(root + '/playwright');
}
const { chromium } = loadPlaywright();

const [BASE, OUT, TOKEN] = process.argv.slice(2);
if (!BASE || !OUT || !TOKEN) {
  console.error('usage: node demo/screenshots.mjs <base-url> <out-dir> <share-token>');
  process.exit(2);
}
const PASSWORD = 'demo';
const SETTLE = 10000;   // چند دور نمونه‌برداریِ ۲ ثانیه‌ای تا sparkline ها پر شوند

async function page(browser, opts = {}) {
  const ctx = await browser.newContext({
    viewport: { width: 1600, height: 1000 }, deviceScaleFactor: 2,
    colorScheme: 'dark', ...opts });
  const p = await ctx.newPage();
  p.on('pageerror', e => { throw new Error('page error: ' + e.message); });
  return p;
}
async function login(p, lang) {
  await p.goto(BASE + '/?lang=' + lang);
  const status = await p.evaluate(async pw => (await fetch('/api/login', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: 'admin', password: pw }) })).status, PASSWORD);
  if (status !== 200) throw new Error('login failed: HTTP ' + status);
  await p.goto(BASE + '/?lang=' + lang);
  await p.waitForTimeout(SETTLE);
}
// بازه‌ای از صفحه بینِ دو y (مختصاتِ کلِ صفحه)
async function clip(p, file, top, bottom) {
  await p.screenshot({ path: `${OUT}/${file}`, fullPage: true,
    clip: { x: 0, y: top, width: p.viewportSize().width, height: bottom - top } });
}
// سطرِ نمودارِ باز (tr.graphrow) و سطرِ کاربرِ بالایش
async function graphBox(p) {
  return p.evaluate(() => {
    const g = document.querySelector('tr.graphrow');
    const r = g.getBoundingClientRect();
    const u = g.previousElementSibling.getBoundingClientRect();
    return { top: u.top + scrollY - 8, bottom: r.bottom + scrollY + 8,
             gtop: r.top + scrollY - 4 };
  });
}

const browser = await chromium.launch();
try {
  let p = await page(browser);
  await login(p, 'en');
  await p.screenshot({ path: `${OUT}/overview.png` });

  // نمودارِ ۳۰ روزه‌ی یک کاربر، و بعد نقشه‌ی حرارتیِ همان
  const row = p.locator('tr', { hasText: 'bob-desktop' }).first();
  await row.getByText('Show chart').click();
  await p.waitForTimeout(1500);
  await p.getByRole('button', { name: '30 days' }).first().click();
  await p.waitForTimeout(2500);
  let b = await graphBox(p);
  await clip(p, 'client-chart.png', b.top, b.bottom);
  await p.locator('tr.graphrow button', { hasText: '🌡' }).first().click();
  await p.waitForTimeout(2500);
  b = await graphBox(p);
  await clip(p, 'heatmap.png', b.gtop, b.bottom);

  // کانفیگ + QR
  await p.goto(BASE + '/?lang=en');
  await p.waitForTimeout(4000);
  await p.locator('tr', { hasText: 'carol-ipad' }).first().getByText('Config / QR').click();
  await p.waitForTimeout(2500);
  await p.screenshot({ path: `${OUT}/config-qr.png` });
  await p.context().close();

  p = await page(browser);
  await login(p, 'fa');
  await p.screenshot({ path: `${OUT}/rtl-fa.png` });
  await p.context().close();

  // تمِ روشن با دکمه‌ی خودِ پنل؛ انتخاب در localStorage ِ همین context می‌ماند
  p = await page(browser);
  await login(p, 'en');
  await p.locator('button', { hasText: '🌙' }).first().click();
  await p.waitForTimeout(2500);
  await p.screenshot({ path: `${OUT}/light.png` });
  await p.context().close();

  p = await page(browser, { viewport: { width: 390, height: 844 },
    deviceScaleFactor: 3, isMobile: true, hasTouch: true, locale: 'en-US' });
  await p.goto(BASE + '/s/' + TOKEN + '?lang=en');
  await p.waitForTimeout(2500);
  await p.screenshot({ path: `${OUT}/share-mobile.png`, fullPage: true });
  await p.context().close();

  // تصویرِ پیش‌نمایشِ مخزن (Settings → Social preview)، با داشبوردِ همین اجرا
  p = await page(browser, { viewport: { width: 1280, height: 640 },
    deviceScaleFactor: 1 });
  const card = new URL('./social-preview.html', import.meta.url);
  card.searchParams.set('img', pathToFileURL(OUT + '/overview.png').href);
  await p.goto(card.href);
  await p.waitForTimeout(1500);
  await p.screenshot({ path: `${OUT}/social-preview.png` });
  await p.context().close();
} finally {
  await browser.close();
}
console.log('screenshots: done');
