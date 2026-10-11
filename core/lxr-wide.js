
/* -- LXR Encoder created by surrre4L
 * LXR-Crypt 2.0 | LXR-Wide
 * Custom byte-to-symbol encoding format.
 * No decryption command is exposed in the web interface.
 */

"use strict";

const LXRWide = (() => {
  const VERSION = "2.0";

  // 64 unique symbols: 2 symbols encode each byte.
  const ALPHABET =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

  const HEADER = "LXR-WIDE:2.0";

  function validateBytes(bytes) {
    if (!(bytes instanceof Uint8Array)) {
      throw new TypeError("Expected Uint8Array input");
    }
  }

  function encode(bytes) {
    validateBytes(bytes);

    let output = HEADER + "\n";

    for (const byte of bytes) {
      output += ALPHABET[(byte >> 4) & 15];
      output += ALPHABET[byte & 15];
    }

    return output;
  }

  function validate(encoded) {
    if (typeof encoded !== "string") {
      return { valid: false, error: "Input must be text" };
    }

    if (!encoded.startsWith(HEADER + "\n")) {
      return { valid: false, error: "Invalid LXR-Wide header" };
    }

    const body = encoded.slice(HEADER.length + 1);

    if (body.length % 2 !== 0) {
      return { valid: false, error: "Incomplete symbol pair" };
    }

    for (const symbol of body) {
      if (!ALPHABET.includes(symbol)) {
        return { valid: false, error: "Invalid LXR-Wide symbol" };
      }
    }

    return {
      valid: true,
      version: VERSION,
      encodedLength: body.length,
    };
  }

  return Object.freeze({
    VERSION,
    encode,
    validate,
  });
})();

if (typeof module !== "undefined" && module.exports) {
  module.exports = LXRWide;
}

if (typeof window !== "undefined") {
  window.LXRWide = LXRWide;
}
