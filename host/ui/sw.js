// Service worker: caches the console shell (HTML, CSS, JS, icons, docs) so the console opens offline.
// It NEVER caches /v1 (API) responses, so data and keys are never stored by the worker.
const VERSION = 'redx-console-v2';
const SHELL = ['/', '/ui/css/app.css', '/ui/js/main.js', '/ui/js/theme-init.js', '/manifest.webmanifest', '/ui/icons/redx.svg', '/ui/icons/redx-192.png'];

self.addEventListener('install', (e) => {
  e.waitUntil(caches.open(VERSION).then((c) => c.addAll(SHELL)).then(() => self.skipWaiting()));
});
self.addEventListener('activate', (e) => {
  e.waitUntil(caches.keys().then((ks) => Promise.all(ks.filter((k) => k !== VERSION).map((k) => caches.delete(k)))).then(() => self.clients.claim()));
});
self.addEventListener('fetch', (e) => {
  const req = e.request;
  const url = new URL(req.url);
  if (req.method !== 'GET' || url.origin !== location.origin) return;
  if (url.pathname.startsWith('/v1/') || url.pathname === '/healthz') return; // never touch the API
  // network first so a new redxd version is picked up at once; fall back to the cache when offline
  e.respondWith(
    fetch(req).then((res) => {
      if (res.ok && (url.pathname === '/' || url.pathname.startsWith('/ui/') || url.pathname === '/manifest.webmanifest')) {
        const copy = res.clone();
        caches.open(VERSION).then((c) => c.put(req, copy));
      }
      return res;
    }).catch(() => caches.match(req).then((r) => r || (req.mode === 'navigate' ? caches.match('/') : Response.error()))),
  );
});
