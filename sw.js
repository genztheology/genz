/* শুধু অ্যাপের খোলস (ছোট ফাইলগুলো) ফোনে রাখে — পড়ার কন্টেন্ট বা ব্যক্তিগত তথ্য কিছুই এখানে জমা হয় না।
   দ্রুত খোলা: আগে ফোনে রাখা কপি সাথে সাথে দেখায়, পেছনে নতুনটা এনে রাখে (পরের বার কাজে লাগে)। */
var C = 'gzt-shell-v5';
var FILES = ['./', './index.html', './admin.html', './config.js', './manifest.json', './admin.webmanifest', './icon-192.png', './icon-512.png', './admin-192.png'];
self.addEventListener('install', function(e) { e.waitUntil(caches.open(C).then(function(c) { return c.addAll(FILES); })); self.skipWaiting(); });
self.addEventListener('activate', function(e) {
  e.waitUntil(caches.keys().then(function(ks) { return Promise.all(ks.filter(function(k) { return k !== C; }).map(function(k) { return caches.delete(k); })); }));
  self.clients.claim();
});
self.addEventListener('fetch', function(e) {
  var u = new URL(e.request.url);
  if (u.origin !== location.origin || e.request.method !== 'GET') return;   // Apps Script-এর কিছুই ধরা হয় না
  e.respondWith(caches.open(C).then(function(c) {
    return c.match(e.request, { ignoreSearch: true }).then(function(hit) {
      var net = fetch(e.request).then(function(r) { if (r && r.ok) c.put(e.request, r.clone()); return r; });
      if (hit) { e.waitUntil(net.catch(function() {})); return hit; }
      return net.catch(function() { return c.match('./index.html'); });
    });
  }));
});
