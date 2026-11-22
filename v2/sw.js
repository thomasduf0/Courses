// Garde l'appli disponible même avec peu de réseau au magasin.
// Fichiers du site et bibliothèque Supabase : réseau d'abord, copie locale si pas de réseau.
// Les échanges avec la base (supabase.co) ne passent jamais par ce cache.
const CACHE = 'courses-v2-1';
const LIB = 'https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2/dist/umd/supabase.js';
const SHELL = ['./', 'index.html', 'style.css', 'app.js', 'manifest.webmanifest', 'icon.svg', 'icon-180.png', 'icon-512.png', LIB];

self.addEventListener('install', (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL)).then(() => self.skipWaiting()));
});
self.addEventListener('activate', (e) => {
  // ne supprime que les anciennes copies de cette version (pas celles de l'ancienne appli)
  e.waitUntil(caches.keys().then((keys) => Promise.all(keys.filter((k) => k.startsWith('courses-v2') && k !== CACHE).map((k) => caches.delete(k)))).then(() => self.clients.claim()));
});
self.addEventListener('fetch', (e) => {
  const url = new URL(e.request.url);
  if (e.request.method !== 'GET') return;
  if (url.origin !== self.location.origin && e.request.url !== LIB) return;
  e.respondWith(
    fetch(e.request)
      .then((res) => {
        if (res.ok) { const copy = res.clone(); caches.open(CACHE).then((c) => c.put(e.request, copy)); }
        return res;
      })
      .catch(() => caches.match(e.request, { ignoreSearch: true }).then((r) => r || caches.match('index.html')))
  );
});
