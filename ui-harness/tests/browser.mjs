// Smoke test for the page's own plumbing: loading, painting and DOM input.
// UI behaviour is covered natively by the Rust tests beside this file.
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, join, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';

const site = fileURLToPath(new URL('../../target/ui-harness-site/', import.meta.url));
const base = '/CrabEFI/'; // GitHub Pages serves the site below the repository name
const types = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.wasm': 'application/wasm', '.svg': 'image/svg+xml' };
const server = createServer(async (request, response) => {
  try {
    const path = new URL(request.url, 'http://localhost').pathname;
    assert(path.startsWith(base));
    const file = join(site, normalize('/' + path.slice(base.length)), path.endsWith('/') ? 'index.html' : '');
    response.setHeader('Content-Type', types[extname(file)]);
    response.end(await readFile(file));
  } catch { response.writeHead(404).end(); }
});
await new Promise((done) => server.listen(0, '127.0.0.1', done));
const browser = await chromium.launch({ executablePath: process.env.CHROMIUM || undefined });
try {
  const page = await browser.newPage({ viewport: { width: 1200, height: 1000 } });
  const errors = [];
  page.on('pageerror', (error) => errors.push(error.message));
  page.on('console', (message) => { if (message.type() === 'error') errors.push(message.text()); });
  const state = () => page.evaluate(() => JSON.parse(document.querySelector('#state').textContent));
  const until = (check, ...args) => page.waitForFunction(check, ...args, { timeout: 5000 });

  await page.goto(`http://127.0.0.1:${server.address().port}${base}`);
  await until(() => document.querySelector('#state').textContent);
  assert.equal((await state()).screen, 'boot');
  assert.equal(await page.locator('#scenario option').count(), 8); // listed by Rust

  // The canvas shows exactly what Rust rendered, with the channels in order.
  await page.locator('#pause').click();
  assert.equal(await page.evaluate(async () => {
    const { Playground } = await import('./pkg/crabefi_ui_harness.js');
    const expected = new Playground(1024, 768, 'normal').rgba();
    const shown = document.querySelector('canvas').getContext('2d').getImageData(0, 0, 1024, 768).data;
    return expected.length === shown.length && expected.every((byte, index) => byte === shown[index]);
  }), true);

  // Keys reach the UI, Shift+Tab does not move DOM focus, and F6 leaves.
  const canvas = page.locator('canvas');
  await canvas.focus();
  await page.keyboard.press('ArrowDown');
  await until(() => JSON.parse(document.querySelector('#state').textContent).selected === 1);
  await page.keyboard.press('Shift+Tab');
  assert.equal(await page.evaluate(() => document.activeElement.id), 'screen');
  await page.keyboard.press('F6');
  assert.equal(await page.evaluate(() => document.activeElement.id), 'scenario');

  // Pointer coordinates follow a framebuffer that CSS has scaled down.
  await page.setViewportSize({ width: 520, height: 900 });
  await page.locator('#resolution').selectOption('800x600');
  const [x, y, width, height] = (await state()).navigation.find((tab) => tab.label === 'Security').rect;
  const box = await canvas.boundingBox();
  assert(box.width < 800);
  await page.mouse.click(box.x + (x + width / 2) * box.width / 800, box.y + (y + height / 2) * box.height / 600);
  await until(() => JSON.parse(document.querySelector('#state').textContent).screen === 'security');

  assert.deepEqual(errors, []);
  console.log('Browser smoke test passed');
} finally {
  await browser.close();
  server.close();
}
