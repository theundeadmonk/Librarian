/**
 * Build-only extension boundary.
 *
 * Site access, native messaging, autofill, and credential capture are
 * intentionally absent until their protocol and threat-model decisions land.
 */
export const foundationStatus = Object.freeze({
  credentialAccessImplemented: false,
  nativeMessagingImplemented: false,
});
