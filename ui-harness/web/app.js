// Browser plumbing only: forward input, advance the clock and paint the
// framebuffer. The UI, its hit-testing and the simulation are Rust.
import init, { Playground } from './pkg/crabefi_ui_harness.js';

const $ = (id) => document.getElementById(id);
const canvas = $('screen');
const context = canvas.getContext('2d', { alpha: false });
let wasm, host, image, last, shown;
let paused = false;

function fail(error) {
  $('error').hidden = false;
  $('error').textContent = String(error?.stack || error);
}
addEventListener('error', (event) => fail(event.error ?? event.message));
addEventListener('unhandledrejection', (event) => fail(event.reason));

function reset() {
  const [width, height] = $('resolution').value.split('x').map(Number);
  const next = new Playground(width, height, $('scenario').value);
  host?.free();
  host = next;
  canvas.width = width;
  canvas.height = height;
  image = context.createImageData(width, height);
  $('fail-writes').checked = JSON.parse(host.state_json()).failWrites;
}

function paint() {
  // A fresh view every frame: Wasm memory moves when it grows.
  const source = new Uint32Array(wasm.memory.buffer, host.pixels_ptr(), host.pixels_len());
  const target = image.data;
  for (let i = 0, offset = 0; i < source.length; i++, offset += 4) {
    const pixel = source[i]; // 0x00RRGGBB
    target[offset] = pixel >>> 16;
    target[offset + 1] = (pixel >>> 8) & 255;
    target[offset + 2] = pixel & 255;
    target[offset + 3] = 255;
  }
  context.putImageData(image, 0, 0);

  // The clock and frame counter change every frame; the rest rarely does.
  const { frames, nowMs, ...state } = JSON.parse(host.state_json());
  const text = JSON.stringify(state, null, 2);
  if (text === shown) return;
  shown = text;
  $('state').textContent = text;
  $('status').textContent = host.ended()
    ? `${state.outcome}: the simulated session ended. Reset to continue.`
    : [state.screen, state.dialog].filter(Boolean).join(' · ');
}

function frame(now) {
  // Hidden tabs get no frames; the cap keeps their absence off the countdown.
  host.advance(paused ? 0 : Math.min(100, Math.round(now - (last ?? now))));
  last = now;
  paint();
  requestAnimationFrame(frame);
}

function position(event) {
  const rect = canvas.getBoundingClientRect();
  return [
    Math.floor((event.clientX - rect.left) * canvas.width / rect.width),
    Math.floor((event.clientY - rect.top) * canvas.height / rect.height),
  ];
}

canvas.addEventListener('keydown', (event) => {
  // The UI owns Tab, so F6 is the way out of the display.
  if (event.key === 'F6') $('scenario').focus();
  else if (event.metaKey || event.altKey || !host.dom_key(event.key, event.ctrlKey, event.shiftKey)) return;
  event.preventDefault();
});
canvas.addEventListener('pointermove', (event) => host.pointer(...position(event)));
canvas.addEventListener('pointerleave', () => host.pointer(-1, -1));
canvas.addEventListener('pointerdown', (event) => {
  canvas.focus({ preventScroll: true });
  event.preventDefault();
  if (event.button === 0 && !host.ended()) host.click(...position(event));
});
canvas.addEventListener('wheel', (event) => {
  event.preventDefault();
  if (!host.ended()) host.scroll(Math.sign(event.deltaY));
}, { passive: false });

$('scenario').addEventListener('change', reset);
$('resolution').addEventListener('change', reset);
$('reset').addEventListener('click', reset);
$('fail-writes').addEventListener('change', (event) => host.set_write_failures(event.target.checked));
$('pause').addEventListener('click', (event) => {
  paused = !paused;
  event.target.setAttribute('aria-pressed', paused);
});

wasm = await init();
for (const [name, label] of JSON.parse(Playground.scenarios())) $('scenario').add(new Option(label, name));
reset();
requestAnimationFrame(frame);
