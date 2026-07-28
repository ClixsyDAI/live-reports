# live-reports

Client-facing HTML reports published via GitHub Pages, so deliverables ship as a link instead of an attachment.

Every report is encrypted at rest with AES-256-GCM. GitHub only ever stores and serves ciphertext. The plaintext exists on the author's machine and in the client's browser after they enter the access code, nowhere else.

**Live:** https://clixsydai.github.io/live-reports/

## This repo is public

Deliberately. GitHub Pages sites are publicly reachable regardless of repo visibility, and Pages on a private repo requires a paid plan, so a private repo would buy nothing here except hidden folder names. Encryption is what gates access, not repo visibility.

Two consequences to keep in mind:

- **Folder names are visible to anyone.** That is why slugs are random hex rather than descriptive. `2026-07-autoaccident-cro` would announce the client and the subject; `a7f3c9e1b204` announces nothing.
- **Every committed file is served and browsable, including this one.** Never put client names, slugs, access codes or URLs in the repo. That inventory lives in `_src/INVENTORY.md`, which is gitignored.

## Publishing a report

1. Put the finished self-contained HTML in `_src/`, named however you like.
   Self-contained means inline CSS and JS, images as `data:` URIs, no relative paths to anything outside the file.
2. Encrypt it:
   ```
   node build-report.mjs _src/whatever.html
   ```
   You are prompted for the access code twice. It is not echoed and does not enter shell history. Minimum 8 characters, enforced. A random slug is generated and printed.
3. Check it locally before pushing:
   ```
   node preview.mjs
   ```
   Open the printed `http://localhost:8787/<slug>/`, enter the code, confirm the report renders. Use localhost rather than opening the file directly: `crypto.subtle` needs a secure context and `file://` is not reliably treated as one.
4. Record the client, slug and code in `_src/INVENTORY.md`.
5. Commit and push. Pages redeploys in roughly 30 to 60 seconds.

To update a published report at the same URL, pass its existing slug: `node build-report.mjs _src/whatever.html --slug a7f3c9e1b204`.

Send the client the URL and the access code **through different channels**. A link and its code in one email means one forwarded email opens the report.

## What the encryption does and does not do

- AES-256-GCM, key derived by PBKDF2-SHA256 at 600,000 iterations, random salt and IV per build. A wrong code fails on the GCM authentication tag rather than returning garbage.
- **Strength is entirely the access code's entropy.** Anyone who fetches the page holds the ciphertext and can brute-force offline with no rate limiting. 600k iterations makes each guess expensive, which is only worth something if the code is unguessable. Use 8+ characters. A 4-digit PIN is 10,000 possibilities and would fall quickly on a GPU.
- One code per report, so a leaked code opens that report only.
- It does not stop a client forwarding the code. Nothing can.
- Lose the code and the published report is unrecoverable. The plaintext in `_src/` is the only copy, so back that up somewhere outside this repo.

## Constraints

- Site max 1 GB, soft bandwidth limit 100 GB/month, soft limit 10 builds/hour.
- Encryption inflates a report by roughly 40 percent, base64 overhead.
- `.nojekyll` is present so Jekyll does not process or skip files.
- Nothing is truly deletable. Removing a report takes it offline but it stays in git history. Publishing to the wrong place needs a history rewrite, not a delete commit.
