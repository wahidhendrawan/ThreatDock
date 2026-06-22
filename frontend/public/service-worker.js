/* Self-destruct service worker — clears all caches and unregisters itself */
self.addEventListener('install', () => {
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => Promise.all(keys.map((k) => caches.delete(k))))
  );
  // Unregister this SW immediately
  self.registration.unregister();
  self.clients.claim();
});
