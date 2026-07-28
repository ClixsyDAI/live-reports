# live-reports

Client-facing HTML reports published via GitHub Pages, so deliverables ship as a link instead of an attachment.

Every report is encrypted at rest. GitHub only ever stores and serves ciphertext. The plaintext exists on your machine and in the client's browser after they enter the access code, nowhere else.

**Live:** https://clixsydai.github.io/live-reports/

## This file is public

Pages serves every file in the repo, including this one at `/README.md`. The repo being private hides the source from GitHub's UI, not from the published site. **Do not put client names, slugs, access codes or URLs in here.** That inventory lives in `_src/INVENTORY.md`, which is gitignored and never leaves your machine.

## Publishing a report

1. Put the finished self-contained HTML in `_src/`, named `YYYY-MM-client-topic.html`.
   Self-contained means inline CSS and JS, images as `data:` URIs, no relative paths to anything outside the file.
2. Encrypt it:
   ```
   node build-report.mjs _src/2026-07-client-topic.html 2026-07-client-topic
   ```
   You will be prompted for the access code twice. It is not echoed and does not enter shell history. Minimum 8 characters, enforced.
3. Check it locally before pushing:
   ```
   node preview.mjs
   ```
   Open `http://localhost:8787/2026-07-client-topic/`, enter the code, confirm the report renders. Use localhost rather than opening the file directly, `crypto.subtle` needs a secure context and `file://` is not reliably treated as one.
4. Record the client, slug and code in `_src/INVENTORY.md`.
5. Commit and push. Pages redeploys in roughly 30 to 60 seconds.

The client gets `https://clixsydai.github.io/live-reports/YYYY-MM-client-topic/` plus the access code. Send the code by a different channel than the link.

## What the encryption does and does not do

- AES-256-GCM, key derived by PBKDF2-SHA256 at 600,000 iterations, random salt and IV per build. Wrong code fails on the GCM authentication tag rather than returning garbage.
- **Strength is entirely the access code's entropy.** An attacker who fetches the page has the ciphertext and can brute-force offline with no rate limiting. 600k iterations makes that expensive per guess, which is only worth anything if the code is unguessable. Use 8+ characters. A 4-digit PIN is 10,000 possibilities and would fall quickly on a GPU.
- One code per report. A leaked code opens that report only.
- It does not stop a client forwarding the code. Nothing can.
- Lose the code and the published report is unrecoverable. The plaintext in `_src/` is your only copy, so back that up somewhere outside this repo.

## Constraints

- Site max 1 GB, soft bandwidth limit 100 GB/month, soft limit 10 builds/hour.
- Encryption inflates a report by roughly 40 percent, base64 overhead.
- `.nojekyll` is present so Jekyll does not process or skip files.
- Nothing is truly deletable. Removing a report takes it offline but it stays in git history. Publishing something to the wrong slug needs a history rewrite, not a delete commit.
