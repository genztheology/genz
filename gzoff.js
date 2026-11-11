/* Gen Z Theology — অফলাইন সংরক্ষণ (v5)
   শিক্ষার্থী যে লেকচার "অফলাইনে সেভ" করে সেটা এই অ্যাপ-মোড়কের (নিজস্ব) স্টোরেজে এনক্রিপ্ট করে রাখা হয়,
   যাতে ইন্টারনেট না থাকলেও অ্যাপ খুলে পড়া যায়।

   নিরাপত্তার ব্যবস্থা (সৎভাবে — কী আটকায়, কী আটকায় না):
   ✔ AES-GCM এনক্রিপশন, চাবি ডিভাইসের বাইরে নেওয়া যায় না (extractable=false)
   ✔ প্রবেশে শিক্ষার্থীর পিন লাগে (PBKDF2 হ্যাশ, ডিভাইসেই যাচাই)
   ✔ মেয়াদ: শেষবার অনলাইনে অ্যাপ খোলার পর "offline_days" দিন (অ্যাডমিন বদলাতে পারেন); পেরোলে অনলাইনে ঢুকে নবায়ন
   ✔ ঘড়ি পিছিয়ে চালানোর চেষ্টা ধরা পড়ে
   ✔ অ্যাডমিন "অফলাইন-সেভ বাতিল" চাপলে পরের অনলাইন খোলায় সব মুছে যায়; লগআউটেও মুছে যায়
   ✔ পড়ার সময় নাম-আইডির জলছাপ
   ✘ কেউ নিজের ফোনে স্ক্রিনশট/ফটো তুললে কোনো অ্যাপই আটকাতে পারে না — জলছাপ ও লিক-ট্রেস সেই কারণেই */
(function(w) {
  'use strict';
  var DB = 'gzt_offline', VER = 1, MAXDRIFT = 5 * 60 * 1000;
  var dbp = null;
  function open() {
    if (dbp) return dbp;
    dbp = new Promise(function(ok, no) {
      var r = indexedDB.open(DB, VER);
      r.onupgradeneeded = function() { var d = r.result; if (!d.objectStoreNames.contains('meta')) d.createObjectStore('meta'); if (!d.objectStoreNames.contains('lec')) d.createObjectStore('lec'); };
      r.onsuccess = function() { ok(r.result); };
      r.onerror = function() { no(r.error); };
    });
    return dbp;
  }
  function tx(store, mode, fn) {
    return open().then(function(d) {
      return new Promise(function(ok, no) {
        var t = d.transaction(store, mode), s = t.objectStore(store), out = fn(s);
        t.oncomplete = function() { ok(out instanceof IDBRequest ? out.result : undefined); };
        t.onerror = t.onabort = function() { no(t.error); };
      });
    });
  }
  function mget(k) { return tx('meta', 'readonly', function(s) { return s.get(k); }); }
  function mset(k, v) { return tx('meta', 'readwrite', function(s) { s.put(v, k); }); }
  function b64(buf) { var a = new Uint8Array(buf), s = ''; for (var i = 0; i < a.length; i++) s += String.fromCharCode(a[i]); return btoa(s); }
  function unb64(s) { var b = atob(s), a = new Uint8Array(b.length); for (var i = 0; i < b.length; i++) a[i] = b.charCodeAt(i); return a; }
  var enc = new TextEncoder(), dec = new TextDecoder();

  function getKey() {
    return mget('ckey').then(function(k) {
      if (k) return k;
      return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']).then(function(nk) { return mset('ckey', nk).then(function() { return nk; }); });
    });
  }
  function pbk(pin, salt) {
    return crypto.subtle.importKey('raw', enc.encode(String(pin)), 'PBKDF2', false, ['deriveBits']).then(function(k) {
      return crypto.subtle.deriveBits({ name: 'PBKDF2', salt: salt, iterations: 120000, hash: 'SHA-256' }, k, 256);
    }).then(b64);
  }
  var G = {
    /* ---- শিক্ষার্থীর পরিচয় ও পিন ---- */
    setAuth: function(code, name, pin) {
      var salt = crypto.getRandomValues(new Uint8Array(16));
      return pbk(pin, salt).then(function(h) { return mset('auth', { code: String(code), name: String(name || ''), salt: b64(salt), h: h }); });
    },
    who: function() { return mget('auth').then(function(a) { return a ? { code: a.code, name: a.name } : null; }); },
    checkPin: function(pin) {
      return mget('auth').then(function(a) {
        if (!a) return false;
        return pbk(pin, unb64(a.salt)).then(function(h) { return h === a.h; });
      });
    },
    /* ---- পোর্টালের সংকেত: অনলাইনে সফলভাবে খুলেছে ---- */
    sync: function(o) {
      var now = Date.now();
      return mget('meta').then(function(m) {
        m = m || {};
        var purge = m.ver && o.ver && String(m.ver) !== String(o.ver);
        var p = purge ? G.purge(true) : Promise.resolve();
        return p.then(function() {
          return mset('meta', { ver: String(o.ver || m.ver || '1'), days: Math.max(1, Number(o.days) || m.days || 14), lastOk: now, maxSeen: now, protect: o.protect !== false, enabled: o.enabled !== false });
        }).then(function() { return { purged: !!purge }; });
      });
    },
    /* ---- সেভ করা লেকচার ---- */
    saveLecture: function(it) {
      return getKey().then(function(key) {
        var iv = crypto.getRandomValues(new Uint8Array(12));
        return crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, key, enc.encode(JSON.stringify(it.data))).then(function(ct) {
          return tx('lec', 'readwrite', function(s) { s.put({ id: String(it.id), title: String(it.title || ''), subject: String(it.subject || ''), savedAt: Date.now(), iv: b64(iv), ct: b64(ct) }, String(it.id)); });
        });
      });
    },
    list: function() {
      return tx('lec', 'readonly', function(s) { return s.getAll(); }).then(function(a) {
        return (a || []).map(function(x) { return { id: x.id, title: x.title, subject: x.subject, savedAt: x.savedAt }; }).sort(function(a, b) { return b.savedAt - a.savedAt; });
      });
    },
    ids: function() { return G.list().then(function(a) { return a.map(function(x) { return x.id; }); }); },
    get: function(id) {
      return Promise.all([getKey(), tx('lec', 'readonly', function(s) { return s.get(String(id)); })]).then(function(r) {
        if (!r[1]) return null;
        return crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(r[1].iv) }, r[0], unb64(r[1].ct)).then(function(pt) { return JSON.parse(dec.decode(pt)); });
      });
    },
    del: function(id) { return tx('lec', 'readwrite', function(s) { s.delete(String(id)); }); },
    purge: function(keepAuth) {
      return tx('lec', 'readwrite', function(s) { s.clear(); }).then(function() { return keepAuth ? 0 : tx('meta', 'readwrite', function(s) { s.clear(); }); });
    },
    /* ---- এখন পড়ার অনুমতি আছে কি? ---- */
    status: function() {
      return Promise.all([mget('meta'), mget('auth'), G.list()]).then(function(r) {
        var m = r[0], a = r[1], n = r[2].length, now = Date.now();
        if (!n) return { ok: false, reason: 'empty', n: 0 };
        if (!m || !a) return { ok: false, reason: 'nosync', n: n };
        if (m.enabled === false) return { ok: false, reason: 'disabled', n: n };
        if (now < (m.maxSeen || 0) - MAXDRIFT) return { ok: false, reason: 'clock', n: n };
        var left = m.lastOk + m.days * 86400000 - now;
        if (left <= 0) return { ok: false, reason: 'expired', n: n, days: m.days };
        mset('meta', Object.assign({}, m, { maxSeen: Math.max(m.maxSeen || 0, now) }));
        return { ok: true, n: n, leftDays: Math.ceil(left / 86400000), who: { code: a.code, name: a.name }, protect: m.protect !== false };
      }).catch(function() { return { ok: false, reason: 'error', n: 0 }; });
    },
    supported: !!(w.indexedDB && w.crypto && w.crypto.subtle)
  };
  w.GZOFF = G;
})(window);
