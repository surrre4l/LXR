
/* -- LXR Encoder created by surrre4L
 * LXR-Crypt 2.0 | LXR Shield
 * Strict structural validation and SHA-256 integrity checks.
 */

"use strict";

const LXRShield = (() => {
  const VERSION = "2.0";
  const HEADER = "LXR-SHIELD:2.0";

  async function sha256(text) {
    if (!globalThis.crypto?.subtle) {
      throw new Error("Web Crypto is unavailable; use HTTPS.");
    }

    const bytes = new TextEncoder().encode(text);
    const digest = await crypto.subtle.digest("SHA-256", bytes);

    return Array.from(new Uint8Array(digest))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }

  async function seal(payload) {
    if (typeof payload !== "string" || payload.length === 0) {
      throw new TypeError("Payload must be non-empty text");
    }

    const digest = await sha256(payload);

    return [
      HEADER,
      "VERSION=" + VERSION,
      "SHA256=" + digest,
      "",
      payload,
    ].join("\n");
  }

  async function validate(sealed) {
    if (typeof sealed !== "string") {
      return { valid: false, error: "Input must be text" };
    }

    const firstBreak = sealed.indexOf("\n");
    if (firstBreak < 0 ||
        sealed.slice(0, firstBreak) !== HEADER) {
      return { valid: false, error: "Invalid Shield header" };
    }

    const secondBreak = sealed.indexOf("\n", firstBreak + 1);
    if (secondBreak < 0) {
      return { valid: false, error: "Missing version metadata" };
    }

    if (sealed.slice(firstBreak + 1, secondBreak) !==
        "VERSION=" + VERSION) {
      return { valid: false, error: "Unsupported version" };
    }

    const thirdBreak = sealed.indexOf("\n", secondBreak + 1);
    if (thirdBreak < 0) {
      return { valid: false, error: "Missing integrity metadata" };
    }

    const hashLine = sealed.slice(secondBreak + 1, thirdBreak);

    if (!/^SHA256=[0-9a-f]{64}$/.test(hashLine)) {
      return { valid: false, error: "Invalid hash metadata" };
    }

    if (sealed.slice(thirdBreak + 1, thirdBreak + 2) !== "\n") {
      return { valid: false, error: "Missing payload separator" };
    }

    const payload = sealed.slice(thirdBreak + 2);
    if (!payload) {
      return { valid: false, error: "Empty payload" };
    }

    const expected = hashLine.slice("SHA256=".length);
    const actual = await sha256(payload);

    if (actual !== expected) {
      return { valid: false, error: "Integrity check failed" };
    }

    return {
      valid: true,
      version: VERSION,
      payload,
    };
  }

  return Object.freeze({ VERSION, seal, validate });
})();

if (typeof module !== "undefined" && module.exports) {
  module.exports = LXRShield;
}

if (typeof window !== "undefined") {
  window.LXRShield = LXRShield;
}
