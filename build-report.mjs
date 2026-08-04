#!/usr/bin/env node
/**
 * build-report.mjs
 *
 * Encrypts a self-contained HTML report so GitHub Pages only ever serves
 * ciphertext. The output is a single HTML file: an unlock form, the encrypted
 * payload, and a WebCrypto routine that decrypts in the browser after a
 * correct passphrase.
 *
 * There is no plaintext in the repo, in git history, or in any HTTP response.
 *
 * Usage:
 *   node build-report.mjs _src/report.html
 *   node build-report.mjs _src/report.html --slug a7f3c9e1b204   # rebuild in place
 *   node build-report.mjs _src/report.html --pass "..."          # non-interactive
 *
 * Omit --pass and you get a hidden prompt with confirmation, which keeps the
 * passphrase out of your shell history. Prefer that.
 *
 * The output folder name is random by default. This repo is public, so a
 * descriptive slug like "2026-07-autoaccident-cro" would tell anyone browsing
 * it who the client is and what was analysed, even though the report itself is
 * encrypted. Record which slug belongs to which client in _src/INVENTORY.md.
 *
 * The gate page follows the Clixsy report kit: kit tokens, kit type stack, the
 * Clixsy wordmark, and no external requests of any kind.
 */

import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { webcrypto as crypto } from 'node:crypto';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ITERATIONS = 600_000;
const SITE = 'https://reports.clixsy.com';
const HERE = dirname(fileURLToPath(import.meta.url));

const b64 = (buf) => Buffer.from(buf).toString('base64');

function die(msg) {
  console.error(`error: ${msg}`);
  process.exit(1);
}

/** Reads a line from the TTY without echoing it. Falls back to piped stdin. */
function askHidden(question) {
  const stdin = process.stdin;
  if (!stdin.isTTY) {
    return new Promise((res) => {
      let buf = '';
      stdin.setEncoding('utf8');
      stdin.on('data', (d) => (buf += d));
      stdin.on('end', () => res(buf.trim()));
    });
  }
  return new Promise((res) => {
    process.stdout.write(question);
    stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding('utf8');
    let buf = '';
    const done = () => {
      stdin.setRawMode(false);
      stdin.pause();
      stdin.removeListener('data', onData);
      process.stdout.write('\n');
      res(buf);
    };
    const onData = (chunk) => {
      for (const ch of chunk) {
        if (ch === '\r' || ch === '\n') return done();
        if (ch === '\u0003') { stdin.setRawMode(false); process.stdout.write('\n'); process.exit(130); }
        if (ch === '\u007f' || ch === '\b') { buf = buf.slice(0, -1); continue; }
        if (ch < ' ') continue;
        buf += ch;
      }
    };
    stdin.on('data', onData);
  });
}

async function encrypt(plaintext, passphrase) {
  const enc = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));

  const material = await crypto.subtle.importKey(
    'raw', enc.encode(passphrase), 'PBKDF2', false, ['deriveKey'],
  );
  const key = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: ITERATIONS, hash: 'SHA-256' },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt'],
  );
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv }, key, enc.encode(plaintext),
  );

  return { v: 1, it: ITERATIONS, salt: b64(salt), iv: b64(iv), ct: b64(ct) };
}

/** Clixsy wordmark. Recolours through --fill-0 and --fill-1, so it works on both themes. */
const WORDMARK = `<svg class="logo" viewBox="0 0 135 32.0865" fill="none" role="img" aria-label="Clixsy">
<path d="M11.1791 0.684635C15.356 -0.557136 20.9827 -0.523849 26.6659 4.35183C27.2434 4.8473 27.3103 5.71756 26.8153 6.2956C26.3203 6.87361 25.4507 6.94067 24.8732 6.44527C20.0114 2.27434 15.3941 2.30755 11.9635 3.32744C6.87212 4.8411 3.72872 8.55438 2.91469 13.8553C2.40409 17.1805 3.00184 21.0434 6.30087 24.6756C9.58803 28.2947 13.3059 29.1522 16.6627 28.8005C20.091 28.4412 23.1659 26.8087 24.9162 25.4256C25.5132 24.9539 26.3793 25.0558 26.8506 25.6533C27.322 26.2509 27.22 27.118 26.6229 27.5897C24.557 29.2222 21.0031 31.1178 16.9494 31.5426C12.8244 31.9748 8.20646 30.8719 4.26276 26.53C0.330954 22.2011 -0.427366 17.4694 0.191876 13.4366C1.15939 7.13587 5.13586 2.48129 11.1791 0.684635ZM59.2993 0.400885C60.0599 0.400947 60.6764 1.01833 60.6764 1.77962V30.1258C60.6764 30.8871 60.0599 31.5045 59.2993 31.5045C58.5387 31.5045 57.9219 30.8871 57.9219 30.1258V1.77962C57.9219 1.01832 58.5387 0.400926 59.2993 0.400885ZM132.476 1.61761C132.898 0.984262 133.754 0.813361 134.387 1.23559C135.019 1.65791 135.19 2.51359 134.769 3.14703L125.961 16.3697V30.1258C125.961 30.8871 125.344 31.5042 124.584 31.5042C123.823 31.5042 123.206 30.8871 123.206 30.1258V15.535L132.476 1.61761ZM88.3298 1.20993C88.8105 0.619956 89.6781 0.531611 90.2676 1.01258C90.8571 1.49366 90.9452 2.36193 90.4646 2.95202L80.1161 15.657L90.1535 27.7563C89.2047 27.9553 88.4102 28.6659 88.1348 29.6387L78.3423 17.8348L67.8681 30.6955C67.3875 31.2856 66.5199 31.3738 65.9303 30.8928C65.3408 30.4118 65.2524 29.5435 65.733 28.9534L88.3298 1.20993ZM32.3294 0.101202C33.0571 0.138092 33.6357 0.740443 33.6358 1.47794V28.1444H53.3488L53.4195 28.146C54.1473 28.1829 54.7262 28.7852 54.7262 29.5228C54.7262 30.2841 54.1095 30.9015 53.3488 30.9015H30.8813V1.47794C30.8814 0.716697 31.4981 0.0995772 32.2587 0.0995354L32.3294 0.101202ZM66.2173 1.02425C66.8004 0.535446 67.6689 0.612208 68.1574 1.19559L77.4892 12.1289C77.9256 12.6403 77.93 13.3919 77.4995 13.9083C76.9519 14.5653 75.9447 14.571 75.3897 13.9203L66.046 2.96635C65.5576 2.38277 65.6343 1.51318 66.2173 1.02425ZM123.726 13.4494C123.188 14.2567 122.009 14.279 121.441 13.4927L115.179 4.83186C116.142 4.70185 116.986 4.04935 117.33 3.09944L123.694 11.8598C124.036 12.3308 124.049 12.965 123.726 13.4494Z" fill="var(--fill-0)"/>
<path clip-rule="evenodd" fill-rule="evenodd" d="M102.056 24.1L102.049 24.1275L102.044 24.1483C101.636 25.7248 100.591 27.9603 98.7189 29.6654C96.7844 31.427 94.0004 32.5788 90.3636 31.8787C89.5094 31.7143 88.9504 30.888 89.1146 30.0334C89.2788 29.1788 90.1042 28.619 90.9585 28.7834C93.5358 29.2795 95.3324 28.4876 96.5992 27.334C97.9193 26.132 98.6958 24.4945 98.9892 23.38C99.6931 20.2623 101.508 12.6372 103.19 6.86626C104.19 3.43443 106.488 1.63144 108.918 0.850818C111.262 0.0982727 113.696 0.294448 115.254 0.698816C116.096 0.917302 116.602 1.77747 116.384 2.61985C116.165 3.46229 115.306 3.96846 114.464 3.74995C113.334 3.45666 111.526 3.32389 109.881 3.85211C108.324 4.35213 106.887 5.43935 106.214 7.74874C104.554 13.4437 102.75 21.022 102.056 24.1Z" fill="var(--fill-1)"/>
</svg>`;

/** Signal favicon, as used by the Signal dashboard. Inlined so the page makes no requests. */
const FAVICON = "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%3E%3Crect width='64' height='64' rx='14' fill='%230b141d'/%3E%3Cpolyline points='10 34 21 34 27 15 37 49 43 34 54 34' fill='none' stroke='%2316DC76' stroke-width='5.5' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E";

/**
 * The gate page deliberately names no client and no report. It is public, so
 * anything written here leaks. Keep it generic.
 */
function page(payload) {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<meta name="color-scheme" content="dark light">
<title>Protected report &middot; Clixsy</title>
<meta name="description" content="A Clixsy client report. An access code is required to open it.">
<meta name="application-name" content="Clixsy Reports">
<meta name="theme-color" content="#070b0e">
<meta property="og:site_name" content="Clixsy">
<meta property="og:title" content="Protected report &middot; Clixsy">
<meta property="og:description" content="A Clixsy client report. An access code is required to open it.">
<meta property="og:type" content="website">
<meta name="twitter:card" content="summary">
<link rel="icon" type="image/svg+xml" href="${FAVICON}">
<style>
  :root {
    --bg:#070b0e; --card:#0d1721; --card2:#101d29; --border:#16242f; --border2:#1d3040;
    --green:#16DC76; --green-soft:rgba(22,220,118,.09); --green-dim:#0f7a44;
    --red:#ff5c5c; --red-soft:rgba(255,92,92,.08);
    --text:#eef4f2; --muted:#8fa3ad; --faint:#5c6e78;
    --fill-0:#eef4f2; --fill-1:#16DC76;
    --font:"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
    --mono:Consolas,"SF Mono",ui-monospace,monospace;
    --radius:14px;
  }
  @media (prefers-color-scheme: light) {
    :root {
      --bg:#eef3f1; --card:#ffffff; --card2:#f3f7f5; --border:#dbe5e1; --border2:#c3d2cc;
      --green:#0eaf62; --green-soft:rgba(14,175,98,.10); --green-dim:#0c8a4e;
      --red:#d84343; --red-soft:rgba(216,67,67,.08);
      --text:#15221c; --muted:#54655f; --faint:#84948e;
      --fill-0:#15221c; --fill-1:#0eaf62;
    }
  }
  * { box-sizing: border-box; }
  body {
    margin:0; min-height:100vh; display:grid; place-items:center; padding:1.5rem;
    background:var(--bg); color:var(--text);
    font-family:var(--font); font-size:16px; line-height:1.55;
    -webkit-font-smoothing:antialiased;
  }
  .card {
    width:100%; max-width:23rem; background:var(--card); border:1px solid var(--border);
    border-radius:var(--radius); padding:2.25rem 1.75rem 1.75rem; text-align:center;
  }
  .logo { width:104px; height:auto; display:block; margin:0 auto 1.75rem; }
  h1 { font-size:1.05rem; font-weight:600; margin:0 0 .35rem; letter-spacing:-.01em; }
  .lede { color:var(--muted); font-size:.875rem; margin:0 0 1.5rem; }
  form { display:flex; flex-direction:column; gap:.6rem; }
  input {
    font-family:var(--mono); font-size:1rem; text-align:center; letter-spacing:.12em;
    padding:.72rem .9rem; border:1px solid var(--border2); border-radius:10px;
    background:var(--card2); color:var(--text); width:100%;
  }
  input::placeholder { color:var(--faint); letter-spacing:.08em; }
  input:focus { outline:none; border-color:var(--green); box-shadow:0 0 0 3px var(--green-soft); }
  button {
    font-family:var(--font); font-size:.95rem; font-weight:600; padding:.72rem .9rem;
    border:0; border-radius:10px; background:var(--green); color:#04120a; cursor:pointer;
  }
  button:hover:not(:disabled) { background:var(--green-dim); color:#eef4f2; }
  button:disabled { opacity:.6; cursor:progress; }
  .msg {
    min-height:1.35rem; margin:.75rem 0 0; font-size:.82rem; color:var(--red);
  }
  .msg:not(:empty) {
    background:var(--red-soft); border-radius:8px; padding:.5rem .6rem;
  }
  .note {
    margin:1.75rem 0 0; padding-top:1.25rem; border-top:1px solid var(--border);
    font-size:.76rem; color:var(--faint);
  }
  .opening { padding:.5rem 0 1rem; }
  .spinner {
    width:26px; height:26px; margin:0 auto .9rem; border-radius:50%;
    border:2px solid var(--border2); border-top-color:var(--green);
    animation:spin .7s linear infinite;
  }
  @keyframes spin { to { transform:rotate(360deg); } }
  @media (prefers-reduced-motion: reduce) {
    .spinner { animation-duration:2.4s; }
  }
  [hidden] { display:none !important; }
</style>
</head>
<body>
  <main class="card">
    ${WORDMARK}

    <div class="opening" id="opening" hidden>
      <div class="spinner"></div>
      <p class="lede" style="margin:0">Opening report</p>
    </div>

    <div id="ui">
      <h1>Protected report</h1>
      <p class="lede">Enter the access code you were sent.</p>
      <form id="gate">
        <input id="pass" type="password" autocomplete="off" autocapitalize="off"
               spellcheck="false" placeholder="Access code" aria-label="Access code">
        <button id="go" type="submit">Unlock</button>
      </form>
      <p class="msg" id="msg" role="status" aria-live="polite"></p>
      <p class="note">Lost your code? Contact your Clixsy account manager.</p>
    </div>
  </main>

<script id="payload" type="application/json">${JSON.stringify(payload)}</script>
<script>
(function () {
  var P = JSON.parse(document.getElementById('payload').textContent);
  var form = document.getElementById('gate');
  var input = document.getElementById('pass');
  var button = document.getElementById('go');
  var msg = document.getElementById('msg');
  var opening = document.getElementById('opening');
  var ui = document.getElementById('ui');

  if (!window.crypto || !window.crypto.subtle) {
    msg.textContent = 'This browser cannot open the report. Try Chrome, Edge, Safari or Firefox.';
    button.disabled = true;
    return;
  }

  function bytes(b64) {
    var bin = atob(b64), out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  async function decrypt(pass) {
    var material = await crypto.subtle.importKey(
      'raw', new TextEncoder().encode(pass), 'PBKDF2', false, ['deriveKey']
    );
    var key = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: bytes(P.salt), iterations: P.it, hash: 'SHA-256' },
      material, { name: 'AES-GCM', length: 256 }, false, ['decrypt']
    );
    // AES-GCM authenticates as it decrypts, so a wrong code throws here
    // rather than returning garbage.
    var plain = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: bytes(P.iv) }, key, bytes(P.ct)
    );
    return new TextDecoder().decode(plain);
  }

  function render(html) {
    // Drop the code from the address bar before painting, so it is not sitting
    // on screen and does not travel if the client copies the URL onward. It
    // stays in browser history regardless, that is unavoidable.
    if (location.hash) {
      try { history.replaceState(null, '', location.pathname + location.search); } catch (e) {}
    }
    // document.write is required rather than innerHTML: the reports carry
    // inline <script> tags, and innerHTML-inserted scripts never execute.
    document.open();
    document.write(html);
    document.close();
  }

  function showForm(message) {
    opening.hidden = true;
    ui.hidden = false;
    button.disabled = false;
    button.textContent = 'Unlock';
    if (message) msg.textContent = message;
    input.value = '';
    input.focus();
  }

  form.addEventListener('submit', async function (e) {
    e.preventDefault();
    var pass = input.value;
    if (!pass) return;

    button.disabled = true;
    button.textContent = 'Unlocking';
    msg.textContent = '';

    try {
      render(await decrypt(pass));
    } catch (err) {
      showForm('That code did not work. Check for stray spaces, it is case sensitive.');
    }
  });

  // One-click links carry the code in the URL fragment. Fragments are never
  // sent to the server, so the code stays out of GitHub's logs and out of
  // Referer headers, and link scanners that fetch the page cannot decrypt it.
  var fragment = location.hash.slice(1);
  if (fragment) {
    ui.hidden = true;
    opening.hidden = false;
    var code;
    try { code = decodeURIComponent(fragment); } catch (e) { code = fragment; }
    decrypt(code).then(render).catch(function () {
      showForm('That link did not open the report. Enter the access code instead.');
    });
  } else {
    input.focus();
  }
})();
</script>
</body>
</html>
`;
}

async function main() {
  const argv = process.argv.slice(2);
  const flagAt = argv.indexOf('--pass');
  let passphrase = null;
  if (flagAt !== -1) {
    passphrase = argv[flagAt + 1];
    if (!passphrase) die('--pass given with no value');
    argv.splice(flagAt, 2);
  }

  const slugAt = argv.indexOf('--slug');
  let slug = null;
  if (slugAt !== -1) {
    slug = argv[slugAt + 1];
    if (!slug) die('--slug given with no value');
    if (!/^[a-z0-9][a-z0-9-]*$/.test(slug)) {
      die(`slug "${slug}" must be lowercase letters, digits and hyphens only`);
    }
    argv.splice(slugAt, 2);
  }

  const [input] = argv;
  if (!input) {
    die('usage: node build-report.mjs <source.html> [--slug <slug>] [--pass "..."]');
  }

  // Random by default. A descriptive folder name would leak the client and the
  // subject matter in a public repo, which defeats the point of encrypting.
  const generated = slug === null;
  if (generated) slug = Buffer.from(crypto.getRandomValues(new Uint8Array(6))).toString('hex');

  const plaintext = await readFile(resolve(input), 'utf8').catch(() => {
    die(`cannot read ${input}`);
  });

  if (passphrase === null) {
    passphrase = await askHidden('Access code: ');
    const again = await askHidden('Confirm:     ');
    if (passphrase !== again) die('codes did not match');
  }
  if (passphrase.length < 8) {
    die('access code must be at least 8 characters. A 4-digit PIN is brute-forceable offline in seconds.');
  }

  const payload = await encrypt(plaintext, passphrase);
  const outDir = resolve(HERE, slug);
  await mkdir(outDir, { recursive: true });
  const outFile = resolve(outDir, 'index.html');
  await writeFile(outFile, page(payload), 'utf8');

  const kb = (n) => `${(n / 1024).toFixed(1)} KB`;
  console.log('');
  console.log(`  source     ${kb(Buffer.byteLength(plaintext))}`);
  console.log(`  encrypted  ${kb(payload.ct.length)} (base64)`);
  console.log(`  kdf        PBKDF2-SHA256, ${ITERATIONS.toLocaleString('en-US')} iterations`);
  console.log(`  cipher     AES-256-GCM`);
  console.log(`  slug       ${slug}${generated ? ' (generated)' : ''}`);
  console.log(`  written    ${outFile}`);
  console.log('');
  console.log(`  preview    http://localhost:8787/${slug}/`);
  console.log('');
  console.log('  Two ways to send it. Pick per client.');
  console.log('');
  console.log('  Two-channel, safer. Send the link and the code separately:');
  console.log(`    ${SITE}/${slug}/`);
  console.log('');
  console.log('  One-click, convenient. The link IS the credential, so anyone');
  console.log('  it is forwarded to gets the report:');
  console.log(`    ${SITE}/${slug}/#${encodeURIComponent(passphrase)}`);
  console.log('');
  console.log('  Record the client, slug and access code in _src/INVENTORY.md,');
  console.log('  then commit and push. The code cannot be recovered if lost.');
}

main().catch((err) => die(err.stack || String(err)));
