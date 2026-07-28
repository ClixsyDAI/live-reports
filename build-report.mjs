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
 */

import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { webcrypto as crypto } from 'node:crypto';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ITERATIONS = 600_000;
const SITE = 'https://clixsydai.github.io/live-reports';
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
<title>Protected report</title>
<style>
  :root { color-scheme: light dark; }
  * { box-sizing: border-box; }
  body {
    margin: 0; min-height: 100vh; display: grid; place-items: center; padding: 1.5rem;
    font: 16px/1.55 ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
    background: #fff; color: #16181d;
  }
  .card { width: 100%; max-width: 22rem; text-align: center; }
  h1 { font-size: 1.15rem; letter-spacing: -0.01em; margin: 0 0 0.4rem; }
  p.lede { color: #6b7280; font-size: 0.9rem; margin: 0 0 1.75rem; }
  form { display: flex; flex-direction: column; gap: 0.6rem; }
  input {
    font: inherit; text-align: center; letter-spacing: 0.08em;
    padding: 0.7rem 0.9rem; border: 1px solid #d1d5db; border-radius: 8px;
    background: #fff; color: inherit;
  }
  input:focus { outline: 2px solid #2563eb; outline-offset: 1px; border-color: transparent; }
  button {
    font: inherit; font-weight: 550; padding: 0.7rem 0.9rem;
    border: 0; border-radius: 8px; background: #16181d; color: #fff; cursor: pointer;
  }
  button:disabled { opacity: 0.55; cursor: progress; }
  .msg { min-height: 1.3rem; margin: 0.5rem 0 0; font-size: 0.85rem; color: #b91c1c; }
  .note { margin-top: 2rem; font-size: 0.78rem; color: #9ca3af; }
  @media (prefers-color-scheme: dark) {
    body { background: #0c0d10; color: #e8eaed; }
    p.lede { color: #9199a5; }
    input { background: #14161b; border-color: #2b2f37; }
    button { background: #e8eaed; color: #0c0d10; }
    .msg { color: #f87171; }
    .note { color: #6b7280; }
  }
</style>
</head>
<body>
  <main class="card">
    <h1>Protected report</h1>
    <p class="lede">Enter the access code you were sent.</p>
    <form id="gate">
      <input id="pass" type="password" autocomplete="off" autocapitalize="off"
             spellcheck="false" aria-label="Access code" autofocus>
      <button id="go" type="submit">Unlock</button>
    </form>
    <p class="msg" id="msg" role="status" aria-live="polite"></p>
    <p class="note">Lost your code? Reply to the email that linked you here.</p>
  </main>

<script id="payload" type="application/json">${JSON.stringify(payload)}</script>
<script>
(function () {
  var P = JSON.parse(document.getElementById('payload').textContent);
  var form = document.getElementById('gate');
  var input = document.getElementById('pass');
  var button = document.getElementById('go');
  var msg = document.getElementById('msg');

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

  form.addEventListener('submit', async function (e) {
    e.preventDefault();
    var pass = input.value;
    if (!pass) return;

    button.disabled = true;
    button.textContent = 'Unlocking';
    msg.textContent = '';

    var html;
    try {
      html = await decrypt(pass);
    } catch (err) {
      button.disabled = false;
      button.textContent = 'Unlock';
      msg.textContent = 'That code did not work.';
      input.value = '';
      input.focus();
      return;
    }

    // document.write is required rather than innerHTML: the reports carry
    // inline <script> tags, and innerHTML-inserted scripts never execute.
    document.open();
    document.write(html);
    document.close();
  });
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
  console.log(`  live       ${SITE}/${slug}/`);
  console.log('');
  console.log('  Record the client, slug and access code in _src/INVENTORY.md,');
  console.log('  then commit and push. The code cannot be recovered if lost.');
}

main().catch((err) => die(err.stack || String(err)));
