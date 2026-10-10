# LXR-Crypt 2.0

A static, browser-local file encryption app designed for GitHub Pages. No build tools or server are required.

## Features

- Encrypt and decrypt files in the browser.
- Password-derived keys using PBKDF2-HMAC-SHA-256 (600,000 iterations).
- AES-256-GCM authenticated encryption through the browser Web Crypto API.
- Continuous LXR encoding using only `A-Z`, `a-z`, and digits `1-5`.
- Preserves the original filename inside the encrypted payload.
- Copy or download `.lxr` output.
- Does not upload files or passwords to a server.
- 25 MiB source-file limit to reduce browser memory issues.

## Deploy to GitHub Pages

1. Create a GitHub repository, for example `lxr-crypt`.
2. Upload `index.html`, `styles.css`, `app.js`, and `README.md` to the repository root.
3. Open **Settings → Pages**.
4. Under **Build and deployment**, choose **Deploy from a branch**.
5. Select the `main` branch and `/ (root)`, then save.
6. Open the published HTTPS URL. Web Crypto requires a secure context; GitHub Pages supplies HTTPS.

## Use

### Encrypt
1. Choose a file or paste text.
2. Enter a password of at least eight characters and confirm it.
3. Press **Encrypt to LXR**.
4. Copy the output or download a `.lxr` file.

### Decrypt
1. Open the Decrypt tab.
2. Import the `.lxr` file or paste its continuous string.
3. Enter the same password.
4. Press **Decrypt and download**.

## Format

After alphabet decoding, the binary payload is:

- 4-byte magic: `LXR2`
- 1-byte format version: `1`
- 16-byte random salt
- 12-byte random AES-GCM nonce
- AES-GCM ciphertext with the 16-byte authentication tag appended by Web Crypto

The full header (magic, version, salt, nonce) is authenticated as AES-GCM additional authenticated data.

The LXR alphabet has 57 characters. Each byte is represented by two characters, where the first is the quotient and the second is the remainder when dividing by 57. Only pairs representing values 0–255 are valid.

## Security notes

- This is a first implementation and should receive independent security review before use for sensitive data.
- A wrong password or modified payload should fail AES-GCM authentication.
- Use a long, unique password. There is no password recovery.
- Anyone with the password and LXR string can decrypt the content.
- Client-side encryption does not make a program impossible to reverse engineer after it is decrypted for execution.
- This app encrypts file bytes; it can process arbitrary files, although it is primarily designed for text-based files. It does not execute or obfuscate code.
- The page's HTML/JavaScript is public by design. Never embed secret keys in the repository.
