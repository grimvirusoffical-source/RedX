import { websiteAuthentication, websiteLoginURL } from './api.js';

const SIGNIN_ATTEMPT = 'redx.website.signinAttempt';

// A DB rejection alone cannot distinguish a signed-out website account from
// an unavailable account authority or integration mismatch. Only the primary
// site's explicit signed_out response starts its existing sign-in flow.
export async function redirectWebsiteSignIn(error, isCurrent = () => true) {
  if (!websiteAuthentication() || error?.status !== 401) return false;
  try {
    if (sessionStorage.getItem(SIGNIN_ATTEMPT) === 'attempted') return false;
    const response = await fetch('/api/accounts/me', {
      credentials: 'same-origin', cache: 'no-store', redirect: 'error',
      signal: AbortSignal.timeout(10000),
    });
    const result = await response.json();
    if (response.status !== 401 || result?.error !== 'signed_out' || !isCurrent() || !websiteAuthentication()) return false;
    if (sessionStorage.getItem(SIGNIN_ATTEMPT) === 'attempted') return false;
    sessionStorage.setItem(SIGNIN_ATTEMPT, 'attempted');
    location.replace(websiteLoginURL());
    return true;
  } catch {
    // If verification, storage or navigation fails, show recovery. Never loop.
    return false;
  }
}

// Clear after canonical DB identity verification, or an explicit recovery click.
export function resetWebsiteSignIn() {
  try { sessionStorage.removeItem(SIGNIN_ATTEMPT); } catch {}
}
