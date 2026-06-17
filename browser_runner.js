#!/usr/bin/env node
'use strict';
const fs = require('fs');
const path = require('path');

const cfgPath = process.argv[2];
if (!cfgPath) {
  process.stderr.write('Usage: node browser_runner.js <config.json>\n');
  process.exit(1);
}

const cfg = JSON.parse(fs.readFileSync(cfgPath, 'utf8'));
const SF = cfg.sessFile;
const RF = cfg.resFile;
const FROM = cfg.from || 0;
const steps = cfg.steps || [];
let V = Object.assign({}, cfg.vars || {});
const R = { steps: [], status: 'done', vars: {}, engine: 'node_playwright' };

if (fs.existsSync(SF)) {
  try {
    const sd = JSON.parse(fs.readFileSync(SF, 'utf8'));
    Object.assign(V, sd.vars || {});
  } catch (e) {}
}

function av(t) {
  t = String(t);
  for (const [k, v] of Object.entries(V)) {
    t = t.split('{' + k + '}').join(String(v));
  }
  return t.replace(/\{random:([^}]+)\}/g, (_, name) => {
    const pts = String(V[name] || '').split(',').map(x => x.trim()).filter(Boolean);
    return pts.length ? pts[Math.floor(Math.random() * pts.length)] : '';
  });
}

const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36';
const STEALTH_ARGS = ['--no-sandbox', '--disable-dev-shm-usage', '--disable-blink-features=AutomationControlled', '--disable-infobars', '--window-size=1920,1080', '--disable-gpu', '--lang=en-IN'];

let playwright, browser, context, page, frameStack = null;

async function main() {
  try {
    playwright = require('playwright');
  } catch (e) {
    R.status = 'error';
    R.error = 'Playwright npm missing. Run: npm install playwright && npx playwright install chromium';
    fs.writeFileSync(RF, JSON.stringify(R));
    process.exit(1);
  }

  let launched = false;
  for (const ch of ['chrome', 'msedge', null]) {
    try {
      browser = await playwright.chromium.launch({
        channel: ch || undefined,
        headless: true,
        args: STEALTH_ARGS
      });
      launched = true;
      break;
    } catch (e) {}
  }
  if (!launched) {
    try {
      browser = await playwright.chromium.launch({ headless: true, args: STEALTH_ARGS });
      launched = true;
    } catch (e) {
      R.status = 'error';
      R.error = 'Could not launch Chromium: ' + e.message;
      fs.writeFileSync(RF, JSON.stringify(R));
      process.exit(1);
    }
  }

  if (FROM > 0 && fs.existsSync(SF)) {
    try {
      const sd = JSON.parse(fs.readFileSync(SF, 'utf8'));
      context = await browser.newContext({
        storageState: sd.storage || undefined,
        userAgent: UA,
        viewport: { width: 1920, height: 1080 },
        locale: 'en-IN',
        timezoneId: 'Asia/Kolkata'
      });
      await context.addInitScript(() => {
        Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
      });
      page = await context.newPage();
      if (sd.url) await goto(sd.url);
      Object.assign(V, sd.vars || {});
    } catch (e) {
      context = await newCtx();
      page = await context.newPage();
    }
  } else {
    context = await newCtx();
    page = await context.newPage();
  }

  async function newCtx() {
    const ctx = await browser.newContext({
      userAgent: UA,
      viewport: { width: 1920, height: 1080 },
      locale: 'en-IN',
      timezoneId: 'Asia/Kolkata'
    });
    await ctx.addInitScript(() => {
      Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
    });
    return ctx;
  }

  function actPage() {
    return frameStack || page;
  }

  async function goto(url) {
    try {
      await page.goto(url, { waitUntil: 'networkidle', timeout: 45000 });
    } catch (e) {
      try {
        await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 45000 });
      } catch (e2) {
        await page.goto(url, { waitUntil: 'load', timeout: 45000 });
      }
    }
  }

  async function ss(crop) {
    const buf = crop && crop.every(Boolean)
      ? await actPage().screenshot({ clip: { x: +crop[0], y: +crop[1], width: +crop[2], height: +crop[3] } })
      : await page.screenshot({ fullPage: false });
    return buf.toString('base64');
  }

  async function fel(sel) {
    const pg = actPage();
    return pg.locator(sel).first();
  }

  for (let i = 0; i < steps.length; i++) {
    if (i < FROM) continue;
    const st = steps[i];
    const t = st.type || 'open';
    try {
      if (t === 'open') {
        frameStack = null;
        await goto(av(st.value || ''));
      } else if (t === 'wait') {
        await new Promise(r => setTimeout(r, parseFloat(av(String(st.value || '2'))) * 1000));
      } else if (t === 'wait_load') {
        await page.waitForLoadState(av(st.value || 'networkidle'), { timeout: (parseFloat(st.timeout || 15) * 1000) });
      } else if (t === 'wait_element') {
        await actPage().waitForSelector(av(st.selector || ''), { timeout: parseFloat(st.timeout || 10) * 1000 });
      } else if (t === 'click') {
        const x = st.x, y = st.y;
        if (x && y) await page.mouse.click(+x, +y);
        else await (await fel(av(st.selector || ''))).click();
      } else if (t === 'fill') {
        await actPage().fill(av(st.selector || ''), av(st.value || ''));
      } else if (t === 'get_text') {
        const txt = await (await fel(av(st.selector || ''))).innerText();
        V[st.var_name || 'result'] = txt;
        R.steps.push({ i, type: t, status: 'ok', value: txt });
        continue;
      } else if (t === 'get_attr') {
        const val = await (await fel(av(st.selector || ''))).getAttribute(av(st.attribute || 'href'));
        V[st.var_name || 'result'] = val || '';
        R.steps.push({ i, type: t, status: 'ok', value: val });
        continue;
      } else if (t === 'js_eval') {
        const val = await page.evaluate(av(st.value || ''));
        V[st.var_name || 'js_result'] = val != null ? String(val) : '';
        R.steps.push({ i, type: t, status: 'ok', value: String(val) });
        continue;
      } else if (t === 'screenshot') {
        const crop = [st.crop_x, st.crop_y, st.crop_w, st.crop_h];
        const b64 = await ss(crop);
        R.steps.push({ i, type: t, status: 'ok', image: b64, send: !!st.send_ss, delete_after: !!st.delete_after, caption: av(st.caption || '') });
        continue;
      } else if (t === 'ask_captcha') {
        const crop = [st.crop_x, st.crop_y, st.crop_w, st.crop_h];
        const b64 = await ss(crop);
        const sd = { url: page.url(), vars: V, resume_from: i + 1, captcha_var: st.var_name || 'captcha', storage: await context.storageState() };
        fs.writeFileSync(SF, JSON.stringify(sd));
        R.status = 'captcha_needed';
        R.captcha_image = b64;
        R.resume_from = i + 1;
        R.captcha_var = st.var_name || 'captcha';
        R.captcha_prompt = av(st.caption || '🔐 Solve captcha & reply:');
        R.steps.push({ i, type: t, status: 'paused' });
        break;
      } else if (t === 'set_var') {
        V[st.var_name || 'v'] = av(st.value || '');
      } else if (t === 'random_var') {
        const pts = av(st.value || '').split(',').map(x => x.trim()).filter(Boolean);
        V[st.var_name || 'v'] = pts.length ? pts[Math.floor(Math.random() * pts.length)] : '';
      } else if (t === 'scroll') {
        await page.mouse.wheel(0, +av(String(st.value || '500')));
      } else if (t === 'reload') {
        await page.reload();
        await page.waitForLoadState('domcontentloaded');
      } else if (t === 'key') {
        await page.keyboard.press(av(st.value || ''));
      } else if (t === 'select') {
        await actPage().selectOption(av(st.selector || ''), av(st.value || ''));
      } else if (t === 'hover') {
        await actPage().hover(av(st.selector || ''));
      } else if (t === 'wait_url') {
        await page.waitForURL('**' + av(st.value || '') + '**', { timeout: parseFloat(st.timeout || 10) * 1000 });
      } else if (t === 'clear_field') {
        await actPage().fill(av(st.selector || ''), '');
      } else if (t === 'double_click') {
        await actPage().dblclick(av(st.selector || ''));
      } else if (t === 'right_click') {
        await actPage().click(av(st.selector || ''), { button: 'right' });
      } else if (t === 'iframe_switch') {
        frameStack = page.frameLocator(av(st.selector || ''));
      } else if (t === 'iframe_main') {
        frameStack = null;
      } else if (t === 'cookie_set') {
        await context.addCookies([{ name: av(st.name || ''), value: av(st.value || ''), url: page.url() }]);
      } else if (t === 'cookie_get') {
        const cks = await context.cookies();
        const match = cks.find(c => c.name === av(st.name || ''));
        V[st.var_name || 'cookie_val'] = match ? match.value : '';
        R.steps.push({ i, type: t, status: 'ok', value: V[st.var_name || 'cookie_val'] });
        continue;
      } else if (t === 'type_slow') {
        const loc = await fel(av(st.selector || ''));
        await loc.click();
        await loc.fill('');
        await loc.type(av(st.value || ''), { delay: parseFloat(st.delay_ms || 80) });
      } else if (t === 'assert_text') {
        const actual = await (await fel(av(st.selector || ''))).innerText();
        const expected = av(st.value || '');
        if (!actual.toLowerCase().includes(expected.toLowerCase())) {
          throw new Error('Assert failed: expected "' + expected + '" in "' + actual + '"');
        }
      } else if (t === 'upload_file') {
        await actPage().setInputFiles(av(st.selector || ''), av(st.value || ''));
      } else if (t === 'drag_drop') {
        await page.dragAndDrop(av(st.selector || ''), av(st.target || ''));
      } else {
        throw new Error('Unknown step type: ' + t);
      }
      R.steps.push({ i, type: t, status: 'ok' });
    } catch (e) {
      R.steps.push({ i, type: t, status: 'error', error: e.message });
      if (st.stop_on_error) {
        R.status = 'error';
        break;
      }
    }
  }

  R.vars = V;
  try {
    if (context) await context.close();
    if (browser) await browser.close();
  } catch (e) {}
  fs.writeFileSync(RF, JSON.stringify(R));
}

main().catch(e => {
  R.status = 'error';
  R.error = e.message;
  fs.writeFileSync(RF, JSON.stringify(R));
  process.exit(1);
});
