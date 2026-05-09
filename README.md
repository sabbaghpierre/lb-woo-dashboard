# lb-woo-dashboard

Static, passphrase-gated dashboard for an internal lead tracker.

The HTML/JS source lives in the [private] tracker repo's `dashboard/` folder
and is synced here by GitHub Actions. The data file (`leads.encrypted.json`)
is **encrypted client-side decryptable**: AES-256-GCM with a key derived from
a passphrase via PBKDF2-SHA256 (200k rounds). Without the passphrase the file
is opaque ciphertext.

> This repo is public so it can be served via free GitHub Pages, but it
> contains no plaintext data.
