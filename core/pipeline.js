
/* -- LXR Encoder created by surrre4L
 * LXR-Crypt 2.0 | Encoding Pipeline
 * Connects LXR-Wide and LXR Shield.
 * No decryption command is provided.
 */

"use strict";

const LXRPipeline = (() => {
  const VERSION = "2.0";
  const WATERMARK = "-- LXR Encoder created by surrre4L";

  async function encodeSource(source) {
    if (typeof source !== "string" || !source.trim()) {
      throw new TypeError("Enter source code first.");
    }

    if (typeof window.LXRWide?.encode !== "function") {
      throw new Error("LXR-Wide is not loaded.");
    }

    if (typeof window.LXRShield?.seal !== "function") {
      throw new Error("LXR Shield is not loaded.");
    }

    // Embed the exact watermark into the original source
    // before encoding it into LXR-Wide symbols.
    const watermarkedSource =
      WATERMARK + "\n" + source;

    const bytes = new TextEncoder().encode(watermarkedSource);
    const widePayload = window.LXRWide.encode(bytes);

    // Seal the encoded representation with integrity metadata.
    const protectedOutput =
      await window.LXRShield.seal(widePayload);

    return {
      version: VERSION,
      watermark: WATERMARK,
      output: protectedOutput,
    };
  }

  return Object.freeze({
    VERSION,
    WATERMARK,
    encodeSource,
  });
})();

window.LXRPipeline = LXRPipeline;
