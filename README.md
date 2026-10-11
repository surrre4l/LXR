# LXR-Crypt 2.0 — Build A (Format Foundation)

A static, browser-local file encryption app designed for GitHub Pages. No build tools or server are required. The official product version remains **2.0** during development; the binary format version is separate.

## Features retained

- Encrypt and decrypt files in the browser.
- Password-derived keys using PBKDF2-HMAC-SHA-256 (600,000 iterations).
- AES-256-GCM authenticated encryption through the browser Web Crypto API.
- Continuous payload encoding using the original 57-character alphabet (`A-Z`, `a-z`, and digits `1-5`).
- Preserves the original filename inside the encrypted payload.
- Copy or download `.lxr` output.
- Does not upload files or passwords to a server.
- 25 MiB source-file limit to reduce browser memory issues.

## Build A additions

- New files use a versioned `LXR2C:` text prefix and a version-2 binary header.
- Header fields include the `LXR2` magic, binary format version, encoding identifier, reserved flags, random salt, and AES-GCM nonce.
- Header bytes are authenticated as AES-GCM additional authenticated data.
- Encrypted envelope metadata includes the safe filename, metadata schema version, and the attribution `LXR Encoder created by surrre4L`. The source file bytes are not modified by this metadata.
- Strict checks reject unsupported versions, unknown encoding identifiers, nonzero reserved flags, invalid lengths, invalid encoded characters, and truncated ciphertext.
- The existing unprefixed version-1 LXR2 format remains readable for backward compatibility.
- `LXR2W:` and encoding identifier `2` are reserved for LXR-Wide, but Wide encoding is **not implemented in this build**.

## Format overview

### New format (version 2)

Text prefix: `LXR2C:`

After decoding the classic 57-character payload alphabet, the binary header is:

| Field | Size | Meaning |
|---|---:|---|
| Magic | 4 bytes | ASCII `LXR2` |
| Format version | 1 byte | `2` |
| Encoding ID | 1 byte | `1` = classic 57-character encoding; `2` reserved for LXR-Wide |
| Flags | 1 byte | Must be `0` in Build A |
| Salt | 16 bytes | Random PBKDF2 salt |
| Nonce | 12 bytes | Random AES-GCM nonce |
| Ciphertext | Variable | Encrypted envelope, followed by the 16-byte GCM authentication tag |

The header is authenticated as AES-GCM additional authenticated data. The encrypted envelope starts with `LXRM`, a metadata schema version, two 16-bit big-endian lengths, the UTF-8 filename, the UTF-8 attribution string, and the original file bytes. The attribution is encrypted rather than exposed as a cleartext header field.

### Legacy format (version 1)

Older files have no text prefix. Their decoded binary payload starts with `LXR2`, version byte `1`, a 16-byte salt, a 12-byte nonce, and AES-GCM ciphertext. Their original filename envelope remains supported. Legacy files do not contain the new attribution metadata.

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
4. Copy the output or download a `.lxr` file. New files begin with `LXR2C:`.

### Decrypt
1. Open the Decrypt tab.
2. Import a `.lxr` file or paste the continuous string.
3. Enter the same password.
4. Press **Decrypt and download**.

## Security notes

- This is a development build and should receive independent security review before use for sensitive data.
- A wrong password or modified payload should fail AES-GCM authentication.
- Use a long, unique password. There is no password recovery.
- Anyone with the password and LXR string can decrypt the content.
- Client-side encryption does not make a program impossible to reverse engineer after it is decrypted for execution.
- This app encrypts file bytes; it can process arbitrary files, although it is primarily designed for text-based files. It does not execute or obfuscate code.
- The page's HTML/JavaScript is public by design. Never embed secret keys in the repository.
- Build A establishes format identifiers and validation rules; it does not yet implement the LXR-Wide alphabet or add the attribution as a source-code comment.

## Official version convention

The official product sequence remains `2.0`, `4.0`, `6.0`, `8.0`, `10.0`. Development labels such as `2.0-dev.1` may be used for interim builds without changing the official version number.
