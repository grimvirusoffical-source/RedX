// UI separation only. Every operation remains authorized by the native API.
// Local database-service administration is preserved in the standalone console.
export const SERVICE_PAGES = new Set(['devices', 'cluster', 'presets', 'join']);

export function databaseNavigation(items, { website = false, owner = false, admin = false } = {}) {
  return items.filter(item => (!item.owner || owner)
    && (!website || (!item.external && !SERVICE_PAGES.has(item.id) && (!item.websiteAdmin || admin))))
    .map(item => website && item.websiteTitle ? { ...item, title: item.websiteTitle } : item);
}

export function databasePageAvailable(page, website) {
  return !website || !SERVICE_PAGES.has(page);
}

export function databaseAccessLabel(who) {
  if (who?.owner === true) return 'Owner · all databases';
  return who?.account?.sub ? 'Private account workspace' : 'Developer key access';
}

// Embedded presentation is opt-in, website-only and same-origin. It never
// accepts identity, roles, tokens or commands from its parent window.
export function embeddedDatabase(website, location, view) {
  if (!website || new URLSearchParams(location?.search || '').get('embed') !== 'site') return false;
  try { return !!view?.parent && view.parent !== view && view.parent.location.origin === location.origin; }
  catch { return false; }
}

export function websiteNavigationLocation(website, location, view) {
  return embeddedDatabase(website, location, view) ? view.parent.location : location;
}
