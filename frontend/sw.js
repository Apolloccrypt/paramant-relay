const CACHE = 'paradrop-v1';
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
  // Network first for API calls
  if (e.request.url.includes('paramant.app') && !e.request.url.includes('/drop')) {
    return;
  }
  e.respondWith(
    fetch(e.request).catch(() => caches.match(e.request))
  );
});
