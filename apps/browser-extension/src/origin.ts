/** Shared canonical HTTPS policy for the issue #17 credential boundary. */
export const MAX_ORIGIN_BYTES = 2048;
export const MAX_BROWSER_URL_BYTES = 16384;

declare const httpsOriginBrand: unique symbol;
export type HttpsOrigin = string & { readonly [httpsOriginBrand]: true };

/** Accept only a canonical, serialized HTTPS origin at a protocol boundary. */
export function parseHttpsOrigin(value: unknown): HttpsOrigin | null {
  if (typeof value !== "string" || value.length > MAX_ORIGIN_BYTES) {
    return null;
  }
  try {
    const parsed = new URL(value);
    // Equality also rejects paths, userinfo, whitespace, Unicode host spelling,
    // backslash repair, explicit default ports, and other noncanonical forms.
    if (parsed.protocol !== "https:" || parsed.origin !== value) {
      return null;
    }
    return value as HttpsOrigin;
  } catch {
    return null;
  }
}

/**
 * Extract an origin from a URL supplied by a browser API, never a page message.
 * Paths, queries, and fragments are discarded here and must not go to the host.
 * Parsing a string does not attest which document the browser actually loaded.
 */
export function originFromBrowserUrl(value: unknown): HttpsOrigin | null {
  if (
    typeof value !== "string" ||
    value.length > MAX_BROWSER_URL_BYTES ||
    new TextEncoder().encode(value).byteLength > MAX_BROWSER_URL_BYTES ||
    /[\u0000-\u0020\u007f\\]/u.test(value)
  ) {
    return null;
  }
  const authority = /^https:\/\/([^/?#]+)/iu.exec(value)?.[1];
  if (authority === undefined || authority.includes("@")) {
    return null;
  }
  try {
    return parseHttpsOrigin(new URL(value).origin);
  } catch {
    return null;
  }
}

/** No registrable-domain, suffix, display-name, or visually similar matching. */
export function exactHttpsOriginMatch(left: unknown, right: unknown): boolean {
  const origin = parseHttpsOrigin(left);
  return origin !== null && origin === parseHttpsOrigin(right);
}
