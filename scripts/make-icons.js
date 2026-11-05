'use strict';
// Builds the app icon and the header logo from the FunGaming pixel-art logo
// (build/fungaming-logo.png). The logo is pixel art, so it is kept here as a grid
// and every size is drawn from the grid instead of scaling a bitmap.
//
// Run with Electron (it needs nativeImage to write PNGs):  npm run icons
// Writes:
//   build/icon.ico          exe, installer and shortcut icon (electron-builder)
//   src/assets/icon.png     window and taskbar icon at runtime
//   src/renderer/logo.svg   header logo, readable in light and dark themes

const fs = require('fs');
const path = require('path');
const { app, nativeImage } = require('electron');

const ROOT = path.join(__dirname, '..');
const YELLOW = [0xf4, 0xc2, 0x1c];
const BLACK = [0, 0, 0];

// Gamepad, one character per pixel: Y yellow, K black, . empty.
const PAD = [
  '.........K.........',
  '.........K.........',
  '..KKKKKKKKKKKKKKK..',
  '.KYYYYYYYYYYYYYYYK.',
  'KYYYYYYYYYYYYYYYYYK',
  'KYYYKYYYYYYYYYKYYYK',
  'KYYKKKYYYYYYYKYKYYK',
  'KYYYKYYYYYYYYYKYYYK',
  'KYYYYYYYKKKYYYYYYYK',
  'KYYYYYYYYYYYYYYYYYK',
  '.KYYYYYKKKKKYYYYYK.',
  '..KKKKK.....KKKKK..',
];

// "FUNGAMING": FUN in yellow, GAMING in black.
const WORD = [
  'YYYYY.Y...Y.Y...Y..KKKK..KKK..K...K.KKK.K...K..KKKK',
  'Y.....Y...Y.YY..Y.K.....K...K.KK.KK..K..KK..K.K....',
  'YYYY..Y...Y.Y.Y.Y.K.KKK.K...K.K.K.K..K..K.K.K.K.KKK',
  'Y.....Y...Y.Y..YY.K...K.KKKKK.K...K..K..K..KK.K...K',
  'Y......YYY..Y...Y..KKKK.K...K.K...K.KKK.K...K..KKKK',
];

// In the original the gamepad's pixels are 1.3x the wordmark's, with a gap of
// 2.5 wordmark pixels between them.
const PAD_SCALE = 1.3;
const GAP = 2.5;

// --- PNG / ICO -------------------------------------------------------------

// Draws the gamepad centered in a size x size square, transparent around it.
// Each output pixel is the average of 8x8 samples, so sizes that don't divide
// evenly (16, 24, 48) come out with soft edges instead of uneven blocks.
function renderPad(size) {
  const cols = PAD[0].length, rows = PAD.length;
  const margin = size >= 64 ? size / 32 : 0;
  const cell = (size - 2 * margin) / cols;
  const ox = margin, oy = (size - rows * cell) / 2;
  const SS = 8;
  const rgba = Buffer.alloc(size * size * 4);
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      let r = 0, g = 0, b = 0, a = 0;
      for (let sy = 0; sy < SS; sy++) {
        for (let sx = 0; sx < SS; sx++) {
          const cx = Math.floor((x + (sx + 0.5) / SS - ox) / cell);
          const cy = Math.floor((y + (sy + 0.5) / SS - oy) / cell);
          const ch = PAD[cy] && PAD[cy][cx];
          const col = ch === 'Y' ? YELLOW : ch === 'K' ? BLACK : null;
          if (col) { r += col[0]; g += col[1]; b += col[2]; a++; }
        }
      }
      const i = (y * size + x) * 4;
      if (a) {
        rgba[i] = Math.round(r / a);
        rgba[i + 1] = Math.round(g / a);
        rgba[i + 2] = Math.round(b / a);
        rgba[i + 3] = Math.round((255 * a) / (SS * SS));
      }
    }
  }
  return rgba;
}

function toPng(rgba, size) {
  const bgra = Buffer.from(rgba);
  for (let i = 0; i < bgra.length; i += 4) { const t = bgra[i]; bgra[i] = bgra[i + 2]; bgra[i + 2] = t; }
  return nativeImage.createFromBitmap(bgra, { width: size, height: size }).toPNG();
}

// ICO with PNG-compressed entries (supported since Windows Vista).
function toIco(pngs) {
  const header = Buffer.alloc(6 + 16 * pngs.length);
  header.writeUInt16LE(0, 0);
  header.writeUInt16LE(1, 2);
  header.writeUInt16LE(pngs.length, 4);
  let offset = header.length;
  pngs.forEach(({ size, data }, n) => {
    const e = 6 + 16 * n;
    header.writeUInt8(size >= 256 ? 0 : size, e);
    header.writeUInt8(size >= 256 ? 0 : size, e + 1);
    header.writeUInt16LE(1, e + 4);   // planes
    header.writeUInt16LE(32, e + 6);  // bits per pixel
    header.writeUInt32LE(data.length, e + 8);
    header.writeUInt32LE(offset, e + 12);
    offset += data.length;
  });
  return Buffer.concat([header, ...pngs.map((p) => p.data)]);
}

// --- SVG -------------------------------------------------------------------

// One path per color class; each horizontal run of pixels becomes one rect.
function runs(grid, ch, scale, dx, dy) {
  let d = '';
  grid.forEach((row, y) => {
    for (let x = 0; x < row.length; x++) {
      if (row[x] !== ch) continue;
      let end = x;
      while (row[end + 1] === ch) end++;
      const n = (v) => +v.toFixed(3);
      d += `M${n(dx + x * scale)} ${n(dy + y * scale)}h${n((end - x + 1) * scale)}v${n(scale)}h${n(-(end - x + 1) * scale)}z`;
      x = end;
    }
  });
  return d;
}

function logoSvg() {
  const width = WORD[0].length;
  const padW = PAD[0].length * PAD_SCALE;
  const padH = PAD.length * PAD_SCALE;
  const padX = (width - padW) / 2;
  const wordY = padH + GAP;
  const height = wordY + WORD.length;
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${width} ${+height.toFixed(3)}" shape-rendering="crispEdges" role="img" aria-label="FunGaming">
<title>FunGaming</title>
<style>.y{fill:#f4c21c}.k{fill:#000}.t{fill:#000}@media (prefers-color-scheme:dark){.t{fill:#e6e8ec}}</style>
<path class="y" d="${runs(PAD, 'Y', PAD_SCALE, padX, 0)}${runs(WORD, 'Y', 1, 0, wordY)}"/>
<path class="k" d="${runs(PAD, 'K', PAD_SCALE, padX, 0)}"/>
<path class="t" d="${runs(WORD, 'K', 1, 0, wordY)}"/>
</svg>
`;
}

// --- main ------------------------------------------------------------------

function write(rel, data) {
  const file = path.join(ROOT, rel);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, data);
  console.log(`wrote ${rel} (${data.length} bytes)`);
}

app.whenReady().then(() => {
  const sizes = [16, 20, 24, 32, 40, 48, 64, 128, 256];
  const pngs = sizes.map((size) => ({ size, data: toPng(renderPad(size), size) }));
  write('build/icon.ico', toIco(pngs));
  write('src/assets/icon.png', pngs.find((p) => p.size === 256).data);
  write('src/renderer/logo.svg', logoSvg());
  app.quit();
}).catch((err) => { console.error(err); app.exit(1); });
