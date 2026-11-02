// Account data in this browser is scoped to the canonical subject returned by
// the authenticated server. Standalone/key-only hosts keep their existing keys.
let accountScope = null;
export function setAccountStorageScope(subject) {
  accountScope = subject === null ? null : String(subject || 'signed-out');
}
export function accountStorageKey(key) {
  return accountScope === null ? key : 'redx.account.' + encodeURIComponent(accountScope) + ':' + key;
}
export const accountLocal = {
  getItem(key) { try { return localStorage.getItem(accountStorageKey(key)); } catch { return null; } },
  setItem(key, value) { try { localStorage.setItem(accountStorageKey(key), value); } catch {} },
  removeItem(key) { try { localStorage.removeItem(accountStorageKey(key)); } catch {} },
};
export const accountTab = {
  getItem(key) { try { return sessionStorage.getItem(accountStorageKey(key)); } catch { return null; } },
  setItem(key, value) { try { sessionStorage.setItem(accountStorageKey(key), value); } catch {} },
  removeItem(key) { try { sessionStorage.removeItem(accountStorageKey(key)); } catch {} },
};
