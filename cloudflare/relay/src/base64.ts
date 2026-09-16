const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;

export function encodeBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/u, "");
}

export function decodeBase64Url(
  value: string,
  expectedBytes: number,
): Uint8Array | null {
  if (!BASE64URL_PATTERN.test(value)) {
    return null;
  }

  const paddingLength = (4 - (value.length % 4)) % 4;
  const base64 = value.replaceAll("-", "+").replaceAll("_", "/");
  const binary = atob(base64 + "=".repeat(paddingLength));
  if (binary.length !== expectedBytes) {
    return null;
  }

  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

