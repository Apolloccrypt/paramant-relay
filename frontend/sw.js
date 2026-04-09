const CACHE = 'paradrop-v2';
const ASSETS = ['/drop', '/noble-mlkem-bundle.js', '/manifest.json'];

self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(ASSETS)));
  self.skipWaiting();
});

self.addEventListener('activate', e => {
  e.waitUntil(caches.keys().then(keys =>
    Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))
  ));
  self.clients.claim();
});

self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);

  // Only handle same-origin requests — let cross-origin (CDNs, tiles) pass through untouched
  if (url.origin !== self.location.origin) return;

  // Network-first for API calls; cache-first for static assets
  if (url.pathname.startsWith('/v2/') || url.hostname.includes('paramant.app') && !url.pathname.startsWith('/drop')) {
    return;
  }

  e.respondWith(
    fetch(e.request)
      .then(res => {
        // Cache successful same-origin responses
        if (res && res.status === 200) {
          const clone = res.clone();
          caches.open(CACHE).then(c => c.put(e.request, clone));
        }
        return res;
      })
      .catch(() => caches.match(e.request).then(cached => cached || fetch(e.request)))
  );
});
