(() => {
  "use strict";

  const $ = (id) => document.getElementById(id);
  const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz12345";
  const MAGIC = new Uint8Array([0x4c, 0x58, 0x52, 0x32]); // LXR2
  const ENVELOPE_MAGIC = new Uint8Array([0x4c, 0x58, 0x52, 0x4d]); // LXRM
  const LEGACY_FORMAT_VERSION = 1;
  const FORMAT_VERSION = 2;
  const ENCODING_CLASSIC57 = 1;
  const ENCODING_WIDE_RESERVED = 2;
  const CLASSIC_PREFIX = "LXR2C:";
  const WIDE_PREFIX = "LXR2W:";
  const WATERMARK = "LXR Encoder created by surrre4L";
  const SALT_LENGTH = 16;
  const IV_LENGTH = 12;
  const PBKDF2_ITERATIONS = 600000;
  const MAX_INPUT_BYTES = 25 * 1024 * 1024; // 25 MiB safety limit for browser memory
  let selectedFile = null;
  let outputString = "";
  let outputFilename = "encrypted.lxr";

  const encoder = new TextEncoder();
  const decoder = new TextDecoder("utf-8", { fatal: true });

  function showMessage(message) {
    const el = $("message");
    el.textContent = message;
    el.classList.remove("hidden");
    $("resultPanel").classList.add("hidden");
  }
  function clearMessage() {
    $("message").textContent = "";
    $("message").classList.add("hidden");
  }
  function setBusy(button, busy, label) {
    button.disabled = busy;
    if (busy) {
      button.dataset.originalText = button.textContent;
      button.textContent = label;
    } else if (button.dataset.originalText) {
      button.textContent = button.dataset.originalText;
      delete button.dataset.originalText;
    }
  }
  function setMode(mode) {
    const encrypt = mode === "encrypt";
    $("encryptPanel").classList.toggle("hidden", !encrypt);
    $("decryptPanel").classList.toggle("hidden", encrypt);
    $("encryptTab").classList.toggle("active", encrypt);
    $("decryptTab").classList.toggle("active", !encrypt);
    $("encryptTab").setAttribute("aria-selected", String(encrypt));
    $("decryptTab").setAttribute("aria-selected", String(!encrypt));
    clearMessage();
    $("resultPanel").classList.add("hidden");
  }

  function concatBytes(...arrays) {
    const size = arrays.reduce((n, a) => n + a.length, 0);
    const result = new Uint8Array(size);
    let offset = 0;
    for (const array of arrays) {
      result.set(array, offset);
      offset += array.length;
    }
    return result;
  }

  function encodeLXR(bytes) {
    // Each byte maps to two base-57 alphabet characters (57^2 > 255).
    let result = "";
    const chunkSize = 16384;
    for (let start = 0; start < bytes.length; start += chunkSize) {
      const end = Math.min(start + chunkSize, bytes.length);
      let chunk = "";
      for (let i = start; i < end; i++) {
        const value = bytes[i];
        chunk += ALPHABET[Math.floor(value / ALPHABET.length)];
        chunk += ALPHABET[value % ALPHABET.length];
      }
      result += chunk;
    }
    return result;
  }

  function decodeLXR(text) {
    const cleaned = text.trim();
    if (!cleaned) throw new Error("Paste an LXR string first.");
    if (cleaned.length % 2 !== 0) throw new Error("The LXR string has an invalid length.");
    if (!/^[A-Za-z1-5]+$/.test(cleaned)) {
      throw new Error("Invalid character found. LXR strings may contain only A–Z, a–z, and digits 1–5.");
    }
    const output = new Uint8Array(cleaned.length / 2);
    for (let i = 0, j = 0; i < cleaned.length; i += 2, j++) {
      const high = ALPHABET.indexOf(cleaned[i]);
      const low = ALPHABET.indexOf(cleaned[i + 1]);
      const value = high * ALPHABET.length + low;
      if (high < 0 || low < 0 || value > 255) {
        throw new Error("The LXR string contains an invalid encoded byte.");
      }
      output[j] = value;
    }
    return output;
  }

  async function deriveKey(password, salt) {
    if (!window.crypto || !crypto.subtle) {
      throw new Error("Web Crypto is unavailable. Open this app on HTTPS, such as GitHub Pages, or on localhost.");
    }
    const material = await crypto.subtle.importKey(
      "raw", encoder.encode(password), "PBKDF2", false, ["deriveKey"]
    );
    return crypto.subtle.deriveKey(
      { name: "PBKDF2", hash: "SHA-256", salt, iterations: PBKDF2_ITERATIONS },
      material,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  }

  function safeBaseName(name) {
    const cleaned = String(name || "recovered.txt").replace(/[\\/\0-\x1f\x7f]/g, "_").trim();
    return cleaned && cleaned !== "." && cleaned !== ".." ? cleaned.slice(0, 180) : "recovered.txt";
  }

  async function getInputBytes() {
    if (selectedFile) {
      if (selectedFile.size > MAX_INPUT_BYTES) {
        throw new Error("This browser version supports files up to 25 MiB. Use a smaller file to avoid running out of memory.");
      }
      return { bytes: new Uint8Array(await selectedFile.arrayBuffer()), filename: safeBaseName(selectedFile.name) };
    }
    const text = $("plainText").value;
    if (!text) throw new Error("Choose a file or enter some text first.");
    const bytes = encoder.encode(text);
    if (bytes.length > MAX_INPUT_BYTES) throw new Error("Text is larger than the 25 MiB safety limit.");
    return { bytes, filename: "pasted-text.txt" };
  }

  // Legacy envelope retained so existing LXR2/version-1 files remain readable.
  function makeLegacyPlainEnvelope(filename, data) {
    const nameBytes = encoder.encode(safeBaseName(filename));
    if (nameBytes.length > 65535) throw new Error("Filename is too long.");
    const nameLength = new Uint8Array([nameBytes.length >>> 8, nameBytes.length & 255]);
    return concatBytes(nameLength, nameBytes, data);
  }

  function parseLegacyPlainEnvelope(bytes) {
    if (bytes.length < 2) throw new Error("Decrypted payload is incomplete.");
    const nameLength = bytes[0] * 256 + bytes[1];
    if (nameLength < 1 || bytes.length < 2 + nameLength) {
      throw new Error("Decrypted payload has invalid file metadata.");
    }
    let decodedName;
    try {
      decodedName = decoder.decode(bytes.subarray(2, 2 + nameLength));
    } catch (_) {
      throw new Error("Decrypted filename metadata is not valid UTF-8.");
    }
    const name = safeBaseName(decodedName);
    return { filename: name, bytes: bytes.slice(2 + nameLength), watermark: null };
  }

  // Version-2 envelope stores attribution as encrypted metadata; source bytes stay unchanged.
  function makeV2PlainEnvelope(filename, data) {
    const nameBytes = encoder.encode(safeBaseName(filename));
    const watermarkBytes = encoder.encode(WATERMARK);
    if (!nameBytes.length || nameBytes.length > 65535) throw new Error("Filename metadata is invalid.");
    if (watermarkBytes.length > 1024) throw new Error("Watermark metadata is too long.");
    const lengths = new Uint8Array([
      nameBytes.length >>> 8, nameBytes.length & 255,
      watermarkBytes.length >>> 8, watermarkBytes.length & 255
    ]);
    return concatBytes(ENVELOPE_MAGIC, new Uint8Array([1]), lengths, nameBytes, watermarkBytes, data);
  }

  function parseV2PlainEnvelope(bytes) {
    const fixedLength = ENVELOPE_MAGIC.length + 1 + 4;
    if (bytes.length < fixedLength) throw new Error("Version-2 decrypted envelope is incomplete.");
    for (let i = 0; i < ENVELOPE_MAGIC.length; i++) {
      if (bytes[i] !== ENVELOPE_MAGIC[i]) throw new Error("Invalid version-2 envelope marker.");
    }
    if (bytes[4] !== 1) throw new Error("Unsupported metadata schema version.");
    const nameLength = bytes[5] * 256 + bytes[6];
    const watermarkLength = bytes[7] * 256 + bytes[8];
    const metadataEnd = fixedLength + nameLength + watermarkLength;
    if (nameLength < 1 || nameLength > 65535 || watermarkLength > 1024 || metadataEnd > bytes.length) {
      throw new Error("Version-2 envelope contains invalid metadata lengths.");
    }
    let filename;
    let watermark;
    try {
      filename = decoder.decode(bytes.subarray(fixedLength, fixedLength + nameLength));
      watermark = decoder.decode(bytes.subarray(fixedLength + nameLength, metadataEnd));
    } catch (_) {
      throw new Error("Version-2 metadata is not valid UTF-8.");
    }
    if (watermark !== WATERMARK) {
      throw new Error("The LXR attribution metadata is missing or unsupported.");
    }
    return {
      filename: safeBaseName(filename),
      watermark,
      bytes: bytes.slice(metadataEnd)
    };
  }

  async function encryptFile() {
    clearMessage();
    const button = $("encryptButton");
    setBusy(button, true, "Encrypting locally…");
    try {
      const password = $("encryptPassword").value;
      if (password.length < 8) throw new Error("Use a password with at least 8 characters.");
      if (password !== $("confirmPassword").value) throw new Error("The passwords do not match.");

      const { bytes, filename } = await getInputBytes();
      const envelope = makeV2PlainEnvelope(filename, bytes);
      const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
      const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
      const key = await deriveKey(password, salt);

      // Header fields are authenticated as AES-GCM additional authenticated data.
      // Encoding ID 2 is reserved for LXR-Wide and is not enabled in this build yet.
      const header = concatBytes(
        MAGIC,
        new Uint8Array([FORMAT_VERSION, ENCODING_CLASSIC57, 0]),
        salt,
        iv
      );
      const encrypted = new Uint8Array(await crypto.subtle.encrypt(
        { name: "AES-GCM", iv, additionalData: header, tagLength: 128 },
        key,
        envelope
      ));
      const payload = concatBytes(header, encrypted);
      outputString = CLASSIC_PREFIX + encodeLXR(payload);
      outputFilename = safeBaseName(filename) + ".lxr";

      $("resultTitle").textContent = "LXR string created";
      $("resultMessage").textContent =
        `${bytes.length.toLocaleString()} source bytes encrypted. Format LXR2C · classic encoding · encrypted attribution metadata included. Output is ${outputString.length.toLocaleString()} characters.`;
      $("resultText").value = outputString;
      $("downloadButton").textContent = "Download .lxr";
      $("copyButton").textContent = "Copy string";
      $("copyButton").classList.remove("hidden");
      $("downloadButton").classList.remove("hidden");
      $("resultPanel").classList.remove("hidden");
      $("resultPanel").scrollIntoView({ behavior: "smooth", block: "nearest" });
    } catch (error) {
      showMessage(error.message || "Encryption failed.");
    } finally {
      setBusy(button, false);
    }
  }

  async function decryptFile() {
    clearMessage();
    const button = $("decryptButton");
    setBusy(button, true, "Decrypting locally…");
    try {
      const password = $("decryptPassword").value;
      if (!password) throw new Error("Enter the password used to encrypt this LXR string.");

      let encoded = $("cipherText").value.trim();
      if (!encoded && $("lxrInput").files[0]) {
        const file = $("lxrInput").files[0];
        if (file.size > MAX_INPUT_BYTES * 2 + 8192) throw new Error("The LXR file exceeds the size limit.");
        encoded = await file.text();
      }
      encoded = encoded.trim();
      if (!encoded) throw new Error("Paste an LXR string or import an .lxr file first.");
      if (encoded.length > MAX_INPUT_BYTES * 2 + 8192) throw new Error("The LXR string exceeds the size limit.");

      let payload;
      let expectedFormat = "legacy";
      if (encoded.startsWith(WIDE_PREFIX)) {
        throw new Error("This file declares LXR-Wide encoding, which is reserved for a future development build and is not enabled yet.");
      } else if (encoded.startsWith(CLASSIC_PREFIX)) {
        expectedFormat = "v2";
        payload = decodeLXR(encoded.slice(CLASSIC_PREFIX.length));
      } else {
        // Unprefixed strings are treated as the original 2.0 format for backward compatibility.
        payload = decodeLXR(encoded);
      }

      if (payload.length > MAX_INPUT_BYTES + 4096) throw new Error("Decoded LXR payload exceeds the supported size limit.");
      const legacyMinimum = MAGIC.length + 1 + SALT_LENGTH + IV_LENGTH + 16;
      const v2Minimum = MAGIC.length + 3 + SALT_LENGTH + IV_LENGTH + 16;
      if (payload.length < (expectedFormat === "v2" ? v2Minimum : legacyMinimum)) {
        throw new Error("This is too short to be a valid LXR-Crypt 2.0 payload.");
      }

      for (let i = 0; i < MAGIC.length; i++) {
        if (payload[i] !== MAGIC[i]) throw new Error("Unrecognized format. This is not an LXR-Crypt payload.");
      }
      const version = payload[MAGIC.length];
      let saltStart;
      let headerLength;
      if (expectedFormat === "legacy") {
        if (version !== LEGACY_FORMAT_VERSION) {
          if (version === FORMAT_VERSION) throw new Error("This version-2 payload is missing its LXR2C format prefix.");
          throw new Error("Unsupported legacy LXR payload version.");
        }
        saltStart = MAGIC.length + 1;
        headerLength = saltStart + SALT_LENGTH + IV_LENGTH;
      } else {
        if (version !== FORMAT_VERSION) throw new Error("The LXR2C prefix does not match the binary format version.");
        const encodingId = payload[MAGIC.length + 1];
        const flags = payload[MAGIC.length + 2];
        if (encodingId === ENCODING_WIDE_RESERVED) {
          throw new Error("The payload declares LXR-Wide encoding, which is not enabled in this build.");
        }
        if (encodingId !== ENCODING_CLASSIC57) throw new Error("Unsupported LXR encoding identifier.");
        if (flags !== 0) throw new Error("Unsupported LXR header flags.");
        saltStart = MAGIC.length + 3;
        headerLength = saltStart + SALT_LENGTH + IV_LENGTH;
      }

      const salt = payload.slice(saltStart, saltStart + SALT_LENGTH);
      const iv = payload.slice(saltStart + SALT_LENGTH, headerLength);
      if (salt.length !== SALT_LENGTH || iv.length !== IV_LENGTH) throw new Error("The LXR header is truncated.");
      const header = payload.slice(0, headerLength);
      const ciphertext = payload.slice(headerLength);
      if (ciphertext.length < 16) throw new Error("The encrypted payload is missing its authentication tag.");
      const key = await deriveKey(password, salt);

      let plaintext;
      try {
        plaintext = new Uint8Array(await crypto.subtle.decrypt(
          { name: "AES-GCM", iv, additionalData: header, tagLength: 128 },
          key,
          ciphertext
        ));
      } catch (_) {
        throw new Error("Decryption failed. The password may be incorrect, or the LXR data may have been changed.");
      }

      let recovered;
      try {
        recovered = expectedFormat === "v2"
          ? parseV2PlainEnvelope(plaintext)
          : parseLegacyPlainEnvelope(plaintext);
      } catch (error) {
        throw new Error(error.message || "Decrypted file metadata is invalid.");
      }

      const blob = new Blob([recovered.bytes], { type: "application/octet-stream" });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = recovered.filename;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      setTimeout(() => URL.revokeObjectURL(url), 30000);

      $("resultTitle").textContent = "File recovered";
      $("resultMessage").textContent = `${recovered.bytes.length.toLocaleString()} bytes authenticated and downloaded as ${recovered.filename}. ${expectedFormat === "v2" ? "LXR2C format and encrypted attribution metadata verified." : "Legacy LXR2 format authenticated."}`;
      $("resultText").value = "";
      $("copyButton").classList.add("hidden");
      $("downloadButton").classList.add("hidden");
      $("resultPanel").classList.remove("hidden");
    } catch (error) {
      showMessage(error.message || "Decryption failed.");
    } finally {
      setBusy(button, false);
    }
  }

  function downloadText(filename, text) {
    const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = filename;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    setTimeout(() => URL.revokeObjectURL(url), 30000);
  }

  $("encryptTab").addEventListener("click", () => setMode("encrypt"));
  $("decryptTab").addEventListener("click", () => setMode("decrypt"));
  $("encryptButton").addEventListener("click", encryptFile);
  $("decryptButton").addEventListener("click", decryptFile);

  $("fileInput").addEventListener("change", (event) => {
    selectedFile = event.target.files[0] || null;
    $("fileLabel").textContent = selectedFile ? selectedFile.name : "Choose a file";
    if (selectedFile) $("plainText").value = "";
    clearMessage();
  });
  $("plainText").addEventListener("input", () => {
    if ($("plainText").value) {
      selectedFile = null;
      $("fileInput").value = "";
      $("fileLabel").textContent = "Choose a file";
    }
  });
  $("lxrInput").addEventListener("change", async (event) => {
    const file = event.target.files[0];
    if (!file) return;
    if (file.size > MAX_INPUT_BYTES * 2 + 8192) {
      showMessage("The LXR file exceeds the size limit.");
      return;
    }
    try {
      $("cipherText").value = (await file.text()).trim();
      clearMessage();
    } catch (_) {
      showMessage("Could not read the selected LXR file.");
    }
  });

  for (const zone of [ $("dropzone") ]) {
    zone.addEventListener("dragover", (event) => {
      event.preventDefault();
      zone.classList.add("dragover");
    });
    zone.addEventListener("dragleave", () => zone.classList.remove("dragover"));
    zone.addEventListener("drop", (event) => {
      event.preventDefault();
      zone.classList.remove("dragover");
      const file = event.dataTransfer.files[0];
      if (file) {
        selectedFile = file;
        $("fileInput").value = "";
        $("fileLabel").textContent = file.name;
        $("plainText").value = "";
        clearMessage();
      }
    });
  }

  document.querySelectorAll("[data-toggle]").forEach((button) => {
    button.addEventListener("click", () => {
      const input = $(button.dataset.toggle);
      const showing = input.type === "text";
      input.type = showing ? "password" : "text";
      button.textContent = showing ? "Show" : "Hide";
    });
  });

  $("copyButton").addEventListener("click", async () => {
    if (!outputString) return;
    try {
      await navigator.clipboard.writeText(outputString);
      $("copyButton").textContent = "Copied ✓";
    } catch (_) {
      $("resultText").focus();
      $("resultText").select();
      showMessage("Clipboard access was blocked. The output is selected; use your device's Copy command.");
    }
  });
  $("downloadButton").addEventListener("click", () => {
    if (outputString) downloadText(outputFilename, outputString);
  });
})();
