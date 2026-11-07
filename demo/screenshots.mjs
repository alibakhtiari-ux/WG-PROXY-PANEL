// اسکرین‌شات‌های README از پنلِ دمو — screenshots.py این را صدا می‌زند.
//
//   node demo/screenshots.mjs <base-url> <out-dir> <share-token>
//
// Playwright لازم دارد (npm install playwright؛ یا نصبِ سراسری). مرورگرِ
// Chromium ِ خودِ Playwright کافی است؛ به فونتِ سیستمی نیازی نیست، چون پنل
// وزیرمتن را درونِ خودش دارد.
import { createRequire } from 'node:module';
import { execSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';
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

// Chromium ِ خودِ Playwright اگر نصب است؛ وگرنه Chrome ِ نصب‌شده‌ی سیستم
const browser = await chromium.launch().catch(() => chromium.launch({ channel: 'chrome' }));
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

  // SvgStudio: نقشه‌ی مسیرِ خروج، ردگیریِ کاربر و خطِ زمانی — توپولوژی از demo/run.py:topology
  p = await page(browser);
  await login(p, 'en');
  await p.evaluate(() => secGo('viz'));
  await p.waitForTimeout(4000);
  await p.locator('#viz-eg-card').screenshot({ path: `${OUT}/egress-map.png` });
  await p.locator('#viz-tl-card').scrollIntoViewIfNeeded();
  await p.waitForTimeout(2500);
  await p.locator('#viz-tl-card').screenshot({ path: `${OUT}/event-timeline.png` });
  // ردگیری پهن‌تر گرفته می‌شود تا نمودار و کشوی امضا کنارِ هم جا شوند
  await p.setViewportSize({ width: 2300, height: 1000 });
  await p.fill('#viz-tr-q', 'dave-android');
  await p.click('#viz-tr-btn');
  await p.waitForTimeout(3000);
  await p.locator('#viz-tr [data-x="s:sig"]').first().click();   // امضای عیب‌یابی در کشو
  await p.waitForTimeout(1200);
  const tr = p.locator('#viz-tr-card');
  await tr.scrollIntoViewIfNeeded();
  await tr.locator('[data-k="fit"]').first().click();   // Fit کشو را نمی‌بیند: نمودار را از زیرش بیرون بکش
  await p.waitForTimeout(800);
  const tb = await tr.boundingBox();
  await p.mouse.move(tb.x + 354, tb.y + 522);
  await p.mouse.down();
  await p.mouse.move(tb.x + 184, tb.y + 522, { steps: 8 });
  await p.mouse.move(tb.x + 14, tb.y + 522, { steps: 8 });
  await p.mouse.up();
  await p.waitForTimeout(800);
  await tr.screenshot({ path: `${OUT}/user-trace.png` });
  await p.keyboard.press('Escape');
  await p.setViewportSize({ width: 1600, height: 1000 });
  // WG-NQMO: بخشِ «کیفیتِ ارتباط» تا پایانِ جدولِ دستگاه‌ها، و پنجره‌ی یک دستگاه
  // (state از demo/run.py:nqmo_demo؛ frank-router تشخیصِ MTU و دو توصیه دارد)
  await p.evaluate(() => secGo('nqmo'));
  await p.waitForTimeout(2500);
  const nq = await p.evaluate(() => {
    const a = document.getElementById('nqmo-admin').getBoundingClientRect();
    const c = document.getElementById('nqmo-peers-card').getBoundingClientRect();
    return { top: a.top + scrollY - 12, bottom: c.bottom + scrollY + 12 };
  });
  await clip(p, 'nqmo-quality.png', nq.top, nq.bottom);
  await p.locator('#nqmo-peers a', { hasText: 'frank-router' }).first().click();
  await p.waitForTimeout(1500);
  await p.locator('#modal-bg .box').screenshot({ path: `${OUT}/nqmo-peer.png` });
  await p.keyboard.press('Escape');
  await p.waitForTimeout(600);
  // مرکزِ رویداد و جست‌وجوی سراسری
  await p.evaluate(() => window.scrollTo(0, 0));
  await p.click('#bell-btn');
  await p.waitForTimeout(1500);
  await p.screenshot({ path: `${OUT}/event-center.png` });
  await p.keyboard.press('Escape');
  await p.waitForTimeout(600);
  await p.keyboard.press('ControlOrMeta+k');
  await p.waitForTimeout(800);
  await p.keyboard.type('wg');   // چند گروه با هم: بخش، کاربر، تونل، اینترفیس
  await p.waitForTimeout(800);
  await p.screenshot({ path: `${OUT}/command-palette.png` });
  // کارپوشه‌ی Excel از همان endpoint ِ دکمه؛ پس از مرکزِ رویداد، چون هر دانلود ممیزی می‌شود؛ تصویرش جدا از Excel ِ واقعی گرفته می‌شود
  for (const lang of ['en', 'fa']) {
    const xl = await p.evaluate(async l => Array.from(new Uint8Array(await (await fetch(
      '/api/report.xlsx?days=30&lang=' + l)).arrayBuffer())), lang);
    writeFileSync(`${OUT}/report-${lang}.xlsx`, Buffer.from(xl));
  }
  await p.context().close();

  p = await page(browser);
  await login(p, 'fa');
  await p.screenshot({ path: `${OUT}/rtl-fa.png` });
  await p.evaluate(() => secGo('viz'));
  await p.waitForTimeout(4000);
  await p.locator('#viz-eg-card').screenshot({ path: `${OUT}/egress-map-fa.png` });
  await p.context().close();

  // کارتِ کاربر روی گوشی (زیرِ ۶۴۰ پیکسل جدول کارت می‌شود)
  p = await page(browser, { viewport: { width: 390, height: 844 },
    deviceScaleFactor: 3, isMobile: true, hasTouch: true, locale: 'en-US' });
  await login(p, 'en');
  await p.evaluate(() => secGo('wg'));
  await p.waitForTimeout(1500);
  await p.screenshot({ path: `${OUT}/mobile-cards.png` });
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
