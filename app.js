'use strict';

/* =====================================================================
   Nos courses — liste de courses partagée Thomas / Mickaël
   La liste est stockée chiffrée dans le dépôt GitHub (data/liste.enc.json).
   Le jeton GitHub est stocké chiffré avec le mot de passe de chacun
   (config/acces.json). Aucun mot de passe n'est écrit en clair dans le code.
   ===================================================================== */

const REPO = { owner: 'thomasduf0', repo: 'Courses', branch: 'main' };
const API = `https://api.github.com/repos/${REPO.owner}/${REPO.repo}`;
const PATH_CONFIG = 'config/acces.json';
const PATH_DATA = 'data/liste.enc.json';
const USERS = {
  thomas: { name: 'Thomas', color: '#2f6f4f' },
  mickael: { name: 'Mickaël', color: '#c4553b' },
};
const ITER = 310000;
const POLL_MS = 4000;
const LS = {
  session: 'courses.session',
  cache: 'courses.cache',
  mode: 'courses.mode',
  collapsed: 'courses.collapsed',
  filter: 'courses.filter',
};
const DEFAULT_CATEGORIES = [
  ['Vrac', '🌾'], ['Fruits et légumes frais', '🥕'], ['Condiments', '🫙'], ['Sec', '🍝'],
  ['Conserves', '🥫'], ['Laiterie', '🥛'], ['Crémerie / Fromages', '🧀'], ['Rayon frais', '🐟'],
  ['Rayon surgelé', '🧊'], ['Boucherie / Boulangerie', '🥩'], ['Rayon petit déjeuner', '☕'],
  ['Rayon douceurs', '🍫'], ['Hygiène / Maison', '🧴'],
];

/* ---------- utilitaires ---------- */
const enc = new TextEncoder();
const dec = new TextDecoder();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const clone = (o) => JSON.parse(JSON.stringify(o));
const uid = () => (crypto.randomUUID ? crypto.randomUUID().replace(/-/g, '') : Date.now().toString(36) + Math.random().toString(36).slice(2)).slice(0, 16);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const norm = (s) => String(s).normalize('NFD').replace(/[̀-ͯ]/g, '').toLowerCase().trim();
const byName = (a, b) => a.name.localeCompare(b.name, 'fr', { sensitivity: 'base' });
const lsGet = (k, d) => { try { const v = localStorage.getItem(k); return v == null ? d : JSON.parse(v); } catch { return d; } };
const lsSet = (k, v) => { try { v == null ? localStorage.removeItem(k) : localStorage.setItem(k, JSON.stringify(v)); } catch { /* stockage indisponible */ } };

/* ---------- chiffrement (WebCrypto) ---------- */
function toB64(buf) {
  const b = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let s = '';
  for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode.apply(null, b.subarray(i, i + 0x8000));
  return btoa(s);
}
function fromB64(s) {
  const bin = atob(s);
  const b = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) b[i] = bin.charCodeAt(i);
  return b;
}
async function passwordKey(password, salt, iterations = ITER) {
  const base = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
const importListKey = (b64) => crypto.subtle.importKey('raw', fromB64(b64), 'AES-GCM', false, ['encrypt', 'decrypt']);
async function seal(key, text) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(text));
  return { iv: toB64(iv), ct: toB64(ct) };
}
async function unseal(key, box) {
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromB64(box.iv) }, key, fromB64(box.ct));
  return dec.decode(pt);
}

/* ---------- GitHub ---------- */
class HttpError extends Error { constructor(status, msg) { super(msg); this.status = status; } }
function ghHeaders(token) {
  const h = { Accept: 'application/vnd.github+json' };
  if (token) h.Authorization = 'Bearer ' + token;
  return h;
}
async function errMsg(r) { try { const j = await r.json(); return j.message || r.statusText; } catch { return r.statusText; } }
async function ghGet(path, { token, etag } = {}) {
  const h = ghHeaders(token);
  if (etag) h['If-None-Match'] = etag;
  const r = await fetch(`${API}/contents/${path}?ref=${REPO.branch}`, { headers: h, cache: 'no-store' });
  if (r.status === 304) return { notModified: true };
  if (r.status === 404) return null;
  if (!r.ok) throw new HttpError(r.status, await errMsg(r));
  const j = await r.json();
  return { sha: j.sha, etag: r.headers.get('ETag'), text: dec.decode(fromB64(j.content.replace(/\s/g, ''))) };
}
async function ghPut(path, text, sha, message, token) {
  const body = { message, content: toB64(enc.encode(text)), branch: REPO.branch };
  if (sha) body.sha = sha;
  const r = await fetch(`${API}/contents/${path}`, {
    method: 'PUT',
    headers: { ...ghHeaders(token), 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!r.ok) {
    const m = await errMsg(r);
    const e = new HttpError(r.status, m);
    e.conflict = r.status === 409 || (r.status === 422 && /sha/i.test(m));
    throw e;
  }
  return (await r.json()).content.sha;
}
async function loadConfig() {
  try {
    const f = await ghGet(PATH_CONFIG, { token: S.token });
    return f ? JSON.parse(f.text) : null;
  } catch (e) {
    if (e.status === 403 || e.status === 429) {
      const r = await fetch(`https://raw.githubusercontent.com/${REPO.owner}/${REPO.repo}/${REPO.branch}/${PATH_CONFIG}?t=${Date.now()}`, { cache: 'no-store' });
      if (r.status === 404) return null;
      if (r.ok) return r.json();
    }
    throw e;
  }
}

/* ---------- modèle de données ---------- */
function initialState() {
  return {
    v: 1, rev: 0, updatedAt: Date.now(), updatedBy: null,
    categories: DEFAULT_CATEGORIES.map(([name, emoji]) => ({ id: uid(), name, emoji, items: [] })),
  };
}
function findItem(st, id) {
  for (const c of st.categories) {
    const i = c.items.findIndex((x) => x.id === id);
    if (i >= 0) return { cat: c, index: i, item: c.items[i] };
  }
  return null;
}
// Chaque modification est une "opération" rejouable sur la dernière version distante :
// deux personnes peuvent modifier en même temps sans s'écraser.
function applyOp(st, op) {
  const cat = (id) => st.categories.find((c) => c.id === id);
  switch (op.t) {
    case 'addItem': { const c = cat(op.cat); if (c && !findItem(st, op.item.id)) c.items.push({ ...op.item }); break; }
    case 'patchItem': { const f = findItem(st, op.id); if (f) Object.assign(f.item, op.patch); break; }
    case 'delItem': { const f = findItem(st, op.id); if (f) f.cat.items.splice(f.index, 1); break; }
    case 'addCat': { if (!cat(op.cat.id)) st.categories.push({ ...op.cat, items: [] }); break; }
    case 'patchCat': { const c = cat(op.id); if (c) Object.assign(c, op.patch); break; }
    case 'delCat': { st.categories = st.categories.filter((c) => c.id !== op.id); break; }
    case 'moveCat': {
      const i = st.categories.findIndex((c) => c.id === op.id);
      const j = i + op.dir;
      if (i >= 0 && j >= 0 && j < st.categories.length) [st.categories[i], st.categories[j]] = [st.categories[j], st.categories[i]];
      break;
    }
    case 'setCard': {
      st.card = { balance: op.balance, at: op.at, by: op.user };
      break;
    }
    case 'finish': {
      for (const id of op.ids) {
        const f = findItem(st, id);
        if (!f) continue;
        if (f.item.inCart) Object.assign(f.item, { needed: false, inCart: false, oos: false });
        else if (f.item.oos) f.item.oos = false; // pas en stock : reste sur la liste
      }
      break;
    }
  }
  return st;
}

/* ---------- état de l'app ---------- */
const S = {
  screen: 'loading', // loading | setup | replace | login | main
  user: null, token: null, listKey: null, listKeyB64: null,
  remote: null, sha: null, etag: null,
  pending: [], inflight: [], flushing: false, flushTimer: null,
  sync: 'idle', syncErr: '', lastSync: 0,
  mode: lsGet(LS.mode, 'maison'),
  filter: lsGet(LS.filter, 'tout'),
  collapsed: new Set(lsGet(LS.collapsed, [])),
  editing: new Set(),
  drafts: {},
  menu: false, cardSheet: null, toast: null, toastTimer: null,
  loginUser: null, error: '', busy: false,
  pollTimer: null, wake: null,
};

function view() {
  if (!S.remote) return null;
  const st = clone(S.remote);
  for (const op of [...S.inflight, ...S.pending]) applyOp(st, op);
  return st;
}
function saveCache() {
  lsSet(LS.cache, { user: S.user, remote: S.remote, sha: S.sha, pending: [...S.inflight, ...S.pending] });
}

/* ---------- synchronisation ---------- */
async function fetchData({ useEtag = false } = {}) {
  const f = await ghGet(PATH_DATA, { token: S.token, etag: useEtag ? S.etag : null });
  if (!f) return null;
  if (f.notModified) return { notModified: true };
  const state = JSON.parse(await unseal(S.listKey, JSON.parse(f.text)));
  return { state, sha: f.sha, etag: f.etag };
}
async function writeData(state, sha, message) {
  const text = JSON.stringify(await seal(S.listKey, JSON.stringify(state)), null, 1);
  return ghPut(PATH_DATA, text, sha, message, S.token);
}
function act(op) {
  S.pending.push(op);
  saveCache();
  render();
  scheduleFlush();
}
function scheduleFlush(ms = 700) {
  clearTimeout(S.flushTimer);
  S.flushTimer = setTimeout(flush, ms);
}
async function flush() {
  if (S.flushing || !S.pending.length || !S.user) return;
  S.flushing = true;
  S.inflight = S.pending;
  S.pending = [];
  setSync('saving');
  try {
    for (let attempt = 0; ; attempt++) {
      try {
        const cur = await fetchData();
        const base = cur ? cur.state : initialState();
        const st = clone(base);
        for (const op of S.inflight) applyOp(st, op);
        st.rev = (base.rev || 0) + 1;
        st.updatedAt = Date.now();
        st.updatedBy = S.user;
        const n = S.inflight.length;
        const sha = await writeData(st, cur && cur.sha, `Liste : ${n} modification${n > 1 ? 's' : ''} (${USERS[S.user].name})`);
        S.remote = st; S.sha = sha; S.etag = null; S.inflight = [];
        break;
      } catch (e) {
        if (e.conflict && attempt < 4) { await sleep(300 + attempt * 500); continue; }
        throw e;
      }
    }
    S.lastSync = Date.now();
    setSync('ok');
  } catch (e) {
    S.pending = S.inflight.concat(S.pending);
    S.inflight = [];
    if (!handleAuthError(e)) setSync('error', e);
    scheduleFlush(6000);
  } finally {
    S.flushing = false;
    saveCache();
    render();
    if (S.pending.length && S.sync === 'ok') scheduleFlush();
  }
}
async function poll() {
  if (!S.user || S.screen !== 'main' || S.flushing || S.pending.length || document.hidden) return;
  try {
    const d = await fetchData({ useEtag: !!S.etag });
    if (!d) return;
    S.lastSync = Date.now();
    if (d.notModified || d.sha === S.sha) { setSync('ok'); return; }
    if (S.remote && (d.state.rev || 0) < (S.remote.rev || 0)) return; // copie en retard côté GitHub
    if (S.flushing || S.pending.length) return; // une modification locale est partie entre-temps
    const from = d.state.updatedBy && d.state.updatedBy !== S.user ? USERS[d.state.updatedBy] : null;
    S.remote = d.state; S.sha = d.sha; S.etag = d.etag;
    saveCache();
    setSync('ok');
    if (from && !S.toast && !S.menu && !S.cardSheet) showToast(`↻ ${from.name} a modifié la liste`);
    else render();
  } catch (e) {
    if (!handleAuthError(e)) setSync('error', e);
  }
}
function handleAuthError(e) {
  if (e && e.status === 401) {
    setSync('error', new Error('Le jeton GitHub a expiré ou a été révoqué. Remplace-le depuis le menu.'));
    return true;
  }
  return false;
}
function setSync(status, err) {
  S.sync = status;
  S.syncErr = err ? (err.status === 403 ? 'Accès refusé par GitHub (droits du jeton ?)' : err.message || String(err)) : '';
  renderSync();
}
function startPolling() {
  clearInterval(S.pollTimer);
  S.pollTimer = setInterval(poll, POLL_MS);
}

/* ---------- connexion / installation ---------- */
async function boot() {
  const sess = lsGet(LS.session, null);
  if (sess && sess.user && sess.token && sess.listKey) {
    S.user = sess.user; S.token = sess.token; S.listKeyB64 = sess.listKey;
    S.listKey = await importListKey(sess.listKey);
    const cache = lsGet(LS.cache, null);
    if (cache && cache.user === sess.user && cache.remote) {
      S.remote = cache.remote; S.sha = cache.sha; S.pending = cache.pending || [];
      S.screen = 'main';
    }
    render();
    await start();
    return;
  }
  render();
  try {
    const cfg = await loadConfig();
    S.screen = cfg ? 'login' : 'setup';
  } catch (e) {
    S.screen = 'login';
    S.error = 'Impossible de joindre GitHub : ' + e.message;
  }
  render();
}
async function start() {
  try {
    const d = await fetchData();
    if (!d) {
      const st = initialState();
      S.sha = await writeData(st, null, 'Création de la liste');
      S.remote = st;
    } else if (!S.remote || (d.state.rev || 0) >= (S.remote.rev || 0)) {
      S.remote = d.state; S.sha = d.sha; S.etag = d.etag;
    }
    S.lastSync = Date.now();
    S.screen = 'main';
    saveCache();
    setSync('ok');
  } catch (e) {
    if (!S.remote) { S.screen = 'main'; }
    if (!handleAuthError(e)) setSync('error', e);
  }
  render();
  startPolling();
  if (S.pending.length) scheduleFlush(300);
  updateWakeLock();
}
async function login(user, password) {
  const cfg = await loadConfig();
  if (!cfg) { S.screen = 'setup'; return; }
  const blob = cfg.users && cfg.users[user];
  if (!blob) throw new Error('Pas encore de compte pour ' + USERS[user].name + '.');
  let secret;
  try {
    const key = await passwordKey(password, fromB64(blob.salt), cfg.iter || ITER);
    secret = JSON.parse(await unseal(key, blob));
  } catch {
    throw new Error('Mot de passe incorrect.');
  }
  S.user = user; S.token = secret.token; S.listKeyB64 = secret.listKey;
  S.listKey = await importListKey(secret.listKey);
  lsSet(LS.session, { user, token: S.token, listKey: S.listKeyB64 });
  const cache = lsGet(LS.cache, null);
  if (cache && cache.user === user && cache.remote) { S.remote = cache.remote; S.sha = cache.sha; S.pending = cache.pending || []; }
  await start();
}
async function setup(token, pwThomas, pwMickael, { keepList = false } = {}) {
  token = token.trim();
  const check = await fetch(API, { headers: ghHeaders(token), cache: 'no-store' });
  if (check.status === 401) throw new Error('Jeton refusé par GitHub. Vérifie qu’il est bien copié en entier.');
  if (!check.ok) throw new Error('Le jeton n’a pas accès au dépôt ' + REPO.repo + ' (' + check.status + ').');

  const listKeyB64 = keepList && S.listKeyB64 ? S.listKeyB64 : toB64(crypto.getRandomValues(new Uint8Array(32)));
  const secret = JSON.stringify({ token, listKey: listKeyB64 });
  const users = {};
  for (const [id, pw] of [['thomas', pwThomas], ['mickael', pwMickael]]) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const box = await seal(await passwordKey(pw, salt), secret);
    users[id] = { salt: toB64(salt), ...box };
  }
  const cfg = { v: 1, iter: ITER, note: 'Jeton GitHub chiffré avec le mot de passe de chacun. Ne pas modifier à la main.', users };

  S.token = token; S.listKeyB64 = listKeyB64; S.listKey = await importListKey(listKeyB64);
  if (!keepList) {
    const existing = await ghGet(PATH_DATA, { token }).catch(() => null);
    const st = initialState();
    S.sha = await writeData(st, existing && existing.sha, 'Création de la liste');
    S.remote = st; S.pending = []; S.inflight = [];
  }
  const existingCfg = await ghGet(PATH_CONFIG, { token }).catch(() => null);
  await ghPut(PATH_CONFIG, JSON.stringify(cfg, null, 2), existingCfg && existingCfg.sha, keepList ? 'Remplacement du jeton GitHub' : 'Création des accès', token);
}
function logout() {
  lsSet(LS.session, null);
  lsSet(LS.cache, null);
  clearInterval(S.pollTimer);
  Object.assign(S, { user: null, token: null, listKey: null, listKeyB64: null, remote: null, sha: null, etag: null, pending: [], inflight: [], menu: false, screen: 'login', loginUser: null, error: '', drafts: {}, editing: new Set() });
  updateWakeLock();
  render();
}

/* ---------- écran allumé pendant les courses ---------- */
async function updateWakeLock() {
  try {
    const want = S.mode === 'courses' && S.screen === 'main' && !document.hidden;
    if (want && !S.wake && 'wakeLock' in navigator) {
      S.wake = await navigator.wakeLock.request('screen');
      S.wake.addEventListener('release', () => { S.wake = null; });
    } else if (!want && S.wake) {
      await S.wake.release();
      S.wake = null;
    }
  } catch { /* non supporté */ }
}

/* ---------- rendu ---------- */
const root = document.getElementById('app');

function captureFocus() {
  const a = document.activeElement;
  if (!a || !a.dataset || !a.dataset.fk) return null;
  return { fk: a.dataset.fk, start: a.selectionStart, end: a.selectionEnd };
}
function restoreFocus(f) {
  if (!f) return;
  const el = root.querySelector(`[data-fk="${CSS.escape(f.fk)}"]`);
  if (!el) return;
  el.focus({ preventScroll: true });
  try { el.setSelectionRange(f.start, f.end); } catch { /* */ }
}
function draft(fk, fallback = '') { return fk in S.drafts ? S.drafts[fk] : fallback; }

function render() {
  const focus = captureFocus();
  let html = '';
  if (S.screen === 'loading') html = renderLoading();
  else if (S.screen === 'setup' || S.screen === 'replace') html = renderSetup();
  else if (S.screen === 'login') html = renderLogin();
  else html = renderMain();
  root.innerHTML = html + renderToast();
  document.body.dataset.screen = S.screen;
  document.body.dataset.mode = S.mode;
  renderSync();
  restoreFocus(focus);
}

function renderLoading() {
  return `<div class="center"><div class="spinner" aria-label="Chargement"></div></div>`;
}

function renderSetup() {
  const replace = S.screen === 'replace';
  return `
  <div class="auth">
    <div class="auth-card">
      <div class="auth-logo">🧺</div>
      <h1>${replace ? 'Remplacer le jeton GitHub' : 'Installation de la liste'}</h1>
      <p class="muted">${replace
        ? 'Colle le nouveau jeton. La liste est conservée. Les deux mots de passe sont nécessaires pour rechiffrer l’accès de chacun.'
        : 'À faire une seule fois. Colle le jeton GitHub (accès en lecture/écriture au dépôt <b>Courses</b>) et choisis le mot de passe de chacun.'}</p>
      <form data-act="setup" autocomplete="off">
        <label>Jeton GitHub
          <input name="token" type="password" data-fk="s:token" value="${esc(draft('s:token'))}" required placeholder="github_pat_…" autocomplete="off" spellcheck="false">
        </label>
        <label>Mot de passe de Thomas
          <input name="pwt" type="text" data-fk="s:pwt" value="${esc(draft('s:pwt'))}" required autocomplete="off" autocapitalize="off" spellcheck="false">
        </label>
        <label>Mot de passe de Mickaël
          <input name="pwm" type="text" data-fk="s:pwm" value="${esc(draft('s:pwm'))}" required autocomplete="off" autocapitalize="off" spellcheck="false">
        </label>
        ${S.error ? `<p class="err">${esc(S.error)}</p>` : ''}
        <button class="btn primary" ${S.busy ? 'disabled' : ''}>${S.busy ? 'Un instant…' : replace ? 'Enregistrer le nouveau jeton' : 'Créer notre liste'}</button>
        ${replace ? '<button type="button" class="btn ghost" data-act="cancelReplace">Annuler</button>' : ''}
      </form>
    </div>
  </div>`;
}

function renderLogin() {
  const u = S.loginUser;
  return `
  <div class="auth">
    <div class="auth-card">
      <div class="auth-logo">🧺</div>
      <h1>Nos courses</h1>
      <p class="muted">Qui fait la liste ?</p>
      <div class="who-pick">
        ${Object.entries(USERS).map(([id, x]) => `
          <button type="button" class="who-btn ${u === id ? 'on' : ''}" data-act="pickUser" data-id="${id}" style="--c:${x.color}">
            <span class="avatar">${x.name[0]}</span><span>${x.name}</span>
          </button>`).join('')}
      </div>
      ${u ? `
      <form data-act="login">
        <label>Mot de passe de ${USERS[u].name}
          <input name="pw" type="password" data-fk="l:pw" value="${esc(draft('l:pw'))}" required autofocus autocomplete="current-password" autocapitalize="off">
        </label>
        <button class="btn primary" ${S.busy ? 'disabled' : ''}>${S.busy ? 'Ouverture…' : 'Entrer'}</button>
      </form>` : ''}
      ${S.error ? `<p class="err">${esc(S.error)}</p>` : ''}
    </div>
  </div>`;
}

function renderMain() {
  const st = view();
  const me = USERS[S.user];
  const all = st ? st.categories.flatMap((c) => c.items) : [];
  const needed = all.filter((i) => i.needed);
  const inCart = needed.filter((i) => i.inCart);
  const oos = needed.filter((i) => i.oos && !i.inCart);
  const handled = inCart.length + oos.length;
  const sub = S.mode === 'courses'
    ? (needed.length ? `${handled} / ${needed.length} traités` : 'Rien à acheter')
    : (needed.length ? `${needed.length} produit${needed.length > 1 ? 's' : ''} à acheter` : 'La liste est vide');

  return `
  <header class="top">
    <div class="brand">
      <h1>Nos courses</h1>
      <p class="sub">${sub} <span id="sync" class="sync"></span></p>
    </div>
    <button class="me" data-act="menu" style="--c:${me.color}" aria-label="Menu (${me.name})">${me.name[0]}</button>
  </header>
  <nav class="modes" role="tablist">
    <button role="tab" data-act="mode" data-v="maison" class="${S.mode === 'maison' ? 'on' : ''}" aria-selected="${S.mode === 'maison'}">🏠 Maison</button>
    <button role="tab" data-act="mode" data-v="courses" class="${S.mode === 'courses' ? 'on' : ''}" aria-selected="${S.mode === 'courses'}">🛒 Aux courses</button>
  </nav>
  <main class="list">
    ${!st ? `<div class="empty"><p>Impossible de charger la liste.</p><button class="btn primary" data-act="retry">Réessayer</button></div>`
      : S.mode === 'courses' ? renderCourses(st, needed, inCart, oos) : renderMaison(st)}
  </main>
  ${S.menu ? renderMenu() : ''}
  ${S.cardSheet ? renderCardSheet(st) : ''}`;
}

function whoDot(item) {
  const u = item.by && USERS[item.by];
  return u ? `<span class="by" style="--c:${u.color}" title="Ajouté par ${u.name}">${u.name[0]}</span>` : '';
}

function renderMaison(st) {
  const onlyNeeded = S.filter === 'liste';
  const cats = st.categories.map((c) => {
    const items = [...c.items].sort(byName).filter((i) => !onlyNeeded || i.needed);
    const n = c.items.filter((i) => i.needed).length;
    const editing = S.editing.has(c.id);
    const collapsed = S.collapsed.has(c.id) && !editing;
    const fk = 'add:' + c.id;
    return `
    <section class="cat ${collapsed ? 'collapsed' : ''} ${editing ? 'editing' : ''}">
      <header class="cat-h">
        <button class="cat-title" data-act="${editing ? 'catEmoji' : 'collapse'}" data-id="${c.id}" aria-expanded="${!collapsed}">
          <span class="emo">${esc(c.emoji || '🛍️')}</span>
          <span class="cat-name">${esc(c.name)}</span>
          ${n ? `<span class="count">${n}</span>` : ''}
        </button>
        ${editing ? `
          <button class="icon" data-act="catUp" data-id="${c.id}" aria-label="Monter">↑</button>
          <button class="icon" data-act="catDown" data-id="${c.id}" aria-label="Descendre">↓</button>
          <button class="icon" data-act="catRename" data-id="${c.id}" aria-label="Renommer">✎</button>
          <button class="icon danger" data-act="catDel" data-id="${c.id}" aria-label="Supprimer la catégorie">🗑</button>` : ''}
        <button class="link" data-act="edit" data-id="${c.id}">${editing ? 'OK' : 'Modifier'}</button>
      </header>
      ${collapsed ? '' : `
      <ul class="items">
        ${items.map((i) => {
          const qk = 'qty:' + i.id;
          return `
          <li class="item ${i.needed ? 'need' : ''}">
            <button class="tap" data-act="need" data-id="${i.id}" aria-pressed="${!!i.needed}">
              <span class="box" aria-hidden="true"></span>
              <span class="nm">${esc(i.name)}</span>
              ${i.needed ? whoDot(i) : ''}
            </button>
            <input class="qty" data-act="qty" data-id="${i.id}" data-fk="${qk}" value="${esc(draft(qk, i.qty || ''))}" placeholder="qté" aria-label="Quantité de ${esc(i.name)}" enterkeyhint="done">
            ${editing ? `
              <button class="icon" data-act="rename" data-id="${i.id}" aria-label="Renommer">✎</button>
              <button class="icon danger" data-act="del" data-id="${i.id}" aria-label="Supprimer ${esc(i.name)}">✕</button>` : ''}
          </li>`;
        }).join('')}
        ${!items.length ? `<li class="none">${onlyNeeded ? 'Rien de coché ici' : 'Aucun produit pour l’instant'}</li>` : ''}
      </ul>
      <form class="add" data-act="add" data-cat="${c.id}">
        <input name="name" data-fk="${fk}" value="${esc(draft(fk))}" placeholder="Ajouter un produit…" autocomplete="off" enterkeyhint="done">
        <input name="qty" class="qty" data-fk="${fk}:q" value="${esc(draft(fk + ':q'))}" placeholder="qté" autocomplete="off" enterkeyhint="done">
        <button class="add-btn" aria-label="Ajouter">+</button>
      </form>`}
    </section>`;
  }).join('');

  return `
  <div class="toolbar">
    <div class="seg">
      <button data-act="filter" data-v="tout" class="${!onlyNeeded ? 'on' : ''}">Tous les produits</button>
      <button data-act="filter" data-v="liste" class="${onlyNeeded ? 'on' : ''}">Seulement cochés</button>
    </div>
  </div>
  ${cats}
  <button class="btn ghost wide" data-act="addCat">+ Nouvelle catégorie</button>`;
}

function renderCourses(st, needed, inCart, oos) {
  if (!needed.length) {
    return `<div class="empty"><div class="big">🧺</div><p>Rien sur la liste.</p><p class="muted">Passe en mode Maison pour cocher ce qu’il faut acheter.</p></div>`;
  }
  const handled = inCart.length + oos.length;
  const pct = Math.round((handled / needed.length) * 100);
  const isTodo = (i) => i.needed && !i.inCart && !i.oos;
  const hasTodo = (c) => c.items.some(isTodo);
  const ordered = [...st.categories.filter(hasTodo), ...st.categories.filter((c) => !hasTodo(c))];
  const cats = ordered.map((c) => {
    const todo = c.items.filter(isTodo).sort(byName);
    const done = c.items.filter((i) => i.needed && i.inCart).sort(byName);
    const missing = c.items.filter((i) => i.needed && !i.inCart && i.oos).sort(byName);
    if (!todo.length && !done.length && !missing.length) return '';
    const row = (i, state) => `
      <li class="item shop ${state}">
        <button class="tap" data-act="cart" data-id="${i.id}" aria-pressed="${state === 'need'}">
          <span class="box" aria-hidden="true"></span>
          <span class="nm">${esc(i.name)}</span>
          ${i.qty ? `<span class="q">${esc(i.qty)}</span>` : ''}
          ${state === 'done' ? '<span class="tag">au panier</span>' : ''}
          ${state === 'oos' ? '<span class="tag oos-tag">pas en stock</span>' : ''}
        </button>
        ${state === 'need' ? `<button class="oos-btn" data-act="oos" data-id="${i.id}" aria-label="${esc(i.name)} pas en stock">Pas en stock</button>` : ''}
      </li>`;
    return `
    <section class="cat ${todo.length ? '' : 'all-done'}">
      <header class="cat-h"><div class="cat-title static">
        <span class="emo">${esc(c.emoji || '🛍️')}</span><span class="cat-name">${esc(c.name)}</span>
        <span class="count">${todo.length || '✓'}</span></div></header>
      <ul class="items">${todo.map((i) => row(i, 'need')).join('')}${done.map((i) => row(i, 'done')).join('')}${missing.map((i) => row(i, 'oos')).join('')}</ul>
    </section>`;
  }).join('');
  return `
  <div class="progress" role="progressbar" aria-valuenow="${pct}" aria-valuemin="0" aria-valuemax="100"><div style="width:${pct}%"></div></div>
  <p class="hint muted">Touche un produit quand il est dans le panier, ou « Pas en stock » s’il manque.</p>
  ${cats}
  <div class="finish-wrap">
    <button class="btn primary wide" data-act="finish" ${handled ? '' : 'disabled'}>
      <span>Terminer les courses</span>${handled ? `<small>${[inCart.length ? `${inCart.length} au panier` : '', oos.length ? `${oos.length} pas en stock` : ''].filter(Boolean).join(' · ')}</small>` : ''}
    </button>
  </div>`;
}

function renderMenu() {
  const me = USERS[S.user];
  return `
  <div class="sheet-bg" data-act="closeMenu"></div>
  <div class="sheet" role="dialog" aria-label="Menu">
    <p class="sheet-who"><span class="avatar" style="--c:${me.color}">${me.name[0]}</span> Connecté en tant que <b>${me.name}</b></p>
    <button class="btn ghost wide" data-act="showCard">💳 Solde Ticket Restaurant</button>
    <button class="btn ghost wide" data-act="refresh">↻ Actualiser la liste</button>
    <button class="btn ghost wide" data-act="uncheckAll">Tout décocher</button>
    <button class="btn ghost wide" data-act="replaceToken">Remplacer le jeton GitHub</button>
    <button class="btn ghost wide danger" data-act="logout">Se déconnecter</button>
    <button class="btn wide" data-act="closeMenu">Fermer</button>
  </div>`;
}

const euros = (n) => new Intl.NumberFormat('fr-FR', { style: 'currency', currency: 'EUR' }).format(n);
function daysSince(ts) {
  const d0 = new Date(ts); d0.setHours(0, 0, 0, 0);
  const d1 = new Date(); d1.setHours(0, 0, 0, 0);
  return Math.max(0, Math.round((d1 - d0) / 86400000));
}
function ageLabel(ts) {
  const d = daysSince(ts);
  return d === 0 ? 'Actualisé aujourd’hui' : d === 1 ? 'Actualisé hier' : `Actualisé il y a ${d} jours`;
}
function renderCardSheet(st) {
  const card = st && st.card;
  const old = card && daysSince(card.at) >= 7;
  return `
  <div class="sheet-bg" data-act="closeCard"></div>
  <div class="sheet card-sheet" role="dialog" aria-label="Solde Ticket Restaurant">
    ${S.cardSheet === 'finish' ? '<p class="sheet-title">Courses terminées 👏</p>' : ''}
    <div class="tr-card">
      <span class="tr-label">💳 Carte Ticket Restaurant</span>
      ${card ? `
        <span class="tr-amount">${euros(card.balance)}</span>
        <span class="tr-age ${old ? 'old' : ''}">${ageLabel(card.at)}${card.by && USERS[card.by] ? ` par ${USERS[card.by].name}` : ''}</span>`
      : `<span class="tr-amount empty">— €</span><span class="tr-age">Aucun solde enregistré</span>`}
    </div>
    <button class="btn primary wide" data-act="setCard">${card ? 'Mettre à jour le solde' : 'Saisir mon solde'}</button>
    <button class="btn wide" data-act="closeCard">Fermer</button>
  </div>`;
}

function renderToast() {
  if (!S.toast) return '';
  return `<div class="toast" role="status"><span>${esc(S.toast.msg)}</span>${S.toast.undo ? '<button data-act="undo">Annuler</button>' : ''}</div>`;
}

function renderSync() {
  const el = document.getElementById('sync');
  if (!el) return;
  const pend = S.pending.length + S.inflight.length;
  el.className = 'sync ' + (S.sync === 'error' ? 'err' : pend ? 'saving' : 'ok');
  el.title = S.sync === 'error' ? S.syncErr : pend ? 'Enregistrement…' : 'À jour';
  el.textContent = S.sync === 'error' ? '· hors ligne' : pend ? '· enregistrement…' : '';
  let banner = document.getElementById('sync-banner');
  if (S.sync === 'error' && S.screen === 'main') {
    if (!banner) {
      banner = document.createElement('div');
      banner.id = 'sync-banner';
      banner.className = 'banner';
      root.prepend(banner);
    }
    banner.textContent = (pend ? `${pend} modification${pend > 1 ? 's' : ''} en attente. ` : '') + S.syncErr;
  } else if (banner) banner.remove();
}

function showToast(msg, undo) {
  clearTimeout(S.toastTimer);
  S.toast = { msg, undo };
  render();
  S.toastTimer = setTimeout(() => { S.toast = null; render(); }, undo ? 5000 : 2500);
}

/* ---------- actions ---------- */
const H = {
  pickUser(b) { S.loginUser = b.dataset.id; S.error = ''; render(); },
  async login(f) {
    if (S.busy) return;
    S.busy = true; S.error = ''; render();
    try { await login(S.loginUser, f.pw.value); delete S.drafts['l:pw']; } catch (e) { S.error = e.message; S.screen = 'login'; }
    S.busy = false; render();
  },
  async setup(f) {
    if (S.busy) return;
    const replace = S.screen === 'replace';
    const [token, pwt, pwm] = [f.token.value, f.pwt.value.trim(), f.pwm.value.trim()];
    if (!pwt || !pwm) { S.error = 'Les deux mots de passe sont nécessaires.'; render(); return; }
    S.busy = true; S.error = ''; render();
    try {
      await setup(token, pwt, pwm, { keepList: replace });
      S.busy = false;
      for (const k of ['s:token', 's:pwt', 's:pwm']) delete S.drafts[k];
      if (replace) {
        lsSet(LS.session, { user: S.user, token: S.token, listKey: S.listKeyB64 });
        S.screen = 'main'; setSync('ok'); showToast('Nouveau jeton enregistré');
      } else {
        S.screen = 'login'; S.token = null; showToast('Liste créée ! Connecte-toi.');
      }
    } catch (e) {
      S.busy = false;
      S.error = e.status === 403
        ? 'Ce jeton peut lire le dépôt mais pas y écrire. Dans GitHub, modifie le jeton : dépôt « Courses » sélectionné et permission « Contents : Read and write ».'
        : e.message;
      render();
    }
  },
  cancelReplace() { S.screen = 'main'; S.error = ''; render(); },
  mode(b) { S.mode = b.dataset.v; lsSet(LS.mode, S.mode); render(); window.scrollTo(0, 0); updateWakeLock(); },
  filter(b) { S.filter = b.dataset.v; lsSet(LS.filter, S.filter); render(); },
  collapse(b) {
    const id = b.dataset.id;
    S.collapsed.has(id) ? S.collapsed.delete(id) : S.collapsed.add(id);
    lsSet(LS.collapsed, [...S.collapsed]); render();
  },
  edit(b) { const id = b.dataset.id; S.editing.has(id) ? S.editing.delete(id) : S.editing.add(id); render(); },
  need(b) {
    const f = findItem(view(), b.dataset.id); if (!f) return;
    const needed = !f.item.needed;
    act({ t: 'patchItem', id: f.item.id, patch: needed ? { needed: true, inCart: false, oos: false, by: S.user, at: Date.now() } : { needed: false, inCart: false, oos: false } });
  },
  oos(b) {
    const f = findItem(view(), b.dataset.id); if (!f) return;
    act({ t: 'patchItem', id: f.item.id, patch: { oos: true, inCart: false } });
  },
  cart(b) {
    const f = findItem(view(), b.dataset.id); if (!f) return;
    act({ t: 'patchItem', id: f.item.id, patch: f.item.oos ? { oos: false, inCart: false } : { inCart: !f.item.inCart } });
    if (navigator.vibrate) navigator.vibrate(15);
  },
  add(f) {
    const catId = f.dataset.cat;
    const fk = 'add:' + catId;
    const name = f.name.value.trim().replace(/\s+/g, ' ');
    const qty = f.qty.value.trim();
    if (!name) { f.name.focus(); return; }
    const st = view();
    const cat = st.categories.find((c) => c.id === catId);
    const dup = cat && cat.items.find((i) => norm(i.name) === norm(name));
    delete S.drafts[fk]; delete S.drafts[fk + ':q'];
    if (dup) {
      act({ t: 'patchItem', id: dup.id, patch: { needed: true, inCart: false, by: S.user, at: Date.now(), ...(qty ? { qty } : {}) } });
      showToast(`« ${dup.name} » était déjà là, je l’ai coché`);
    } else {
      act({ t: 'addItem', cat: catId, item: { id: uid(), name: name[0].toUpperCase() + name.slice(1), qty, needed: true, inCart: false, by: S.user, at: Date.now() } });
    }
    const input = root.querySelector(`[data-fk="${CSS.escape(fk)}"]`);
    if (input) input.focus();
  },
  qty(el) {
    const fk = el.dataset.fk;
    delete S.drafts[fk];
    const f = findItem(view(), el.dataset.id);
    if (!f || (f.item.qty || '') === el.value.trim()) return;
    act({ t: 'patchItem', id: f.item.id, patch: { qty: el.value.trim() } });
  },
  rename(b) {
    const f = findItem(view(), b.dataset.id); if (!f) return;
    const name = (prompt('Nouveau nom', f.item.name) || '').trim();
    if (name && name !== f.item.name) act({ t: 'patchItem', id: f.item.id, patch: { name } });
  },
  del(b) {
    const f = findItem(view(), b.dataset.id); if (!f) return;
    const item = clone(f.item); const cat = f.cat.id;
    act({ t: 'delItem', id: item.id });
    showToast(`« ${item.name} » supprimé`, () => act({ t: 'addItem', cat, item }));
  },
  addCat() {
    const name = (prompt('Nom de la nouvelle catégorie') || '').trim();
    if (!name) return;
    const emoji = (prompt('Un emoji pour la reconnaître ? (facultatif)', '🛍️') || '🛍️').trim();
    const id = uid();
    act({ t: 'addCat', cat: { id, name, emoji } });
    S.editing.delete(id);
    setTimeout(() => window.scrollTo({ top: document.body.scrollHeight, behavior: 'smooth' }), 50);
  },
  catRename(b) {
    const c = view().categories.find((x) => x.id === b.dataset.id); if (!c) return;
    const name = (prompt('Nouveau nom de la catégorie', c.name) || '').trim();
    if (name && name !== c.name) act({ t: 'patchCat', id: c.id, patch: { name } });
  },
  catEmoji(b) {
    const c = view().categories.find((x) => x.id === b.dataset.id); if (!c) return;
    const emoji = (prompt('Emoji de la catégorie', c.emoji || '') || '').trim();
    if (emoji && emoji !== c.emoji) act({ t: 'patchCat', id: c.id, patch: { emoji } });
  },
  catUp(b) { act({ t: 'moveCat', id: b.dataset.id, dir: -1 }); },
  catDown(b) { act({ t: 'moveCat', id: b.dataset.id, dir: 1 }); },
  catDel(b) {
    const c = view().categories.find((x) => x.id === b.dataset.id); if (!c) return;
    const msg = c.items.length
      ? `Supprimer « ${c.name} » et ses ${c.items.length} produit${c.items.length > 1 ? 's' : ''} ?`
      : `Supprimer la catégorie « ${c.name} » ?`;
    if (!confirm(msg)) return;
    S.editing.delete(c.id);
    act({ t: 'delCat', id: c.id });
  },
  finish() {
    const st = view();
    const all = st.categories.flatMap((c) => c.items).filter((i) => i.needed);
    const done = all.filter((i) => i.inCart);
    const missing = all.filter((i) => !i.inCart && i.oos);
    const left = all.length - done.length - missing.length;
    const pr = (n) => `${n} produit${n > 1 ? 's' : ''}`;
    const rest = (n) => (n > 1 ? 'restent' : 'reste');
    const lines = ['Terminer les courses ?'];
    if (done.length) lines.push(`• ${pr(done.length)} au panier : retiré${done.length > 1 ? 's' : ''} de la liste`);
    if (missing.length) lines.push(`• ${pr(missing.length)} pas en stock : ${rest(missing.length)} sur la liste`);
    if (left) lines.push(`• ${pr(left)} non traité${left > 1 ? 's' : ''} : ${rest(left)} sur la liste`);
    if (!confirm(lines.join('\n'))) return;
    S.cardSheet = 'finish';
    act({ t: 'finish', ids: [...done, ...missing].map((i) => i.id) });
  },
  uncheckAll() {
    const st = view();
    const ids = st.categories.flatMap((c) => c.items).filter((i) => i.needed).map((i) => i.id);
    S.menu = false;
    if (!ids.length) { render(); return; }
    if (!confirm(`Décocher les ${ids.length} produits de la liste ?`)) { render(); return; }
    for (const id of ids) S.pending.push({ t: 'patchItem', id, patch: { needed: false, inCart: false, oos: false } });
    saveCache(); render(); scheduleFlush();
  },
  showCard() { S.menu = false; S.cardSheet = 'menu'; render(); },
  closeCard() { S.cardSheet = null; render(); },
  setCard() {
    const card = view().card;
    const raw = prompt('Solde actuel de la carte Ticket Restaurant (en €)', card ? String(card.balance).replace('.', ',') : '');
    if (raw == null) return;
    const n = Number(raw.replace(/[€\s]/g, '').replace(',', '.'));
    if (!raw.trim() || !Number.isFinite(n) || n < 0) { showToast('Montant non reconnu'); return; }
    act({ t: 'setCard', user: S.user, balance: Math.round(n * 100) / 100, at: Date.now() });
  },
  menu() { S.menu = true; render(); },
  closeMenu() { S.menu = false; render(); },
  async refresh() { S.menu = false; render(); S.etag = null; await poll(); showToast('Liste à jour'); },
  retry() { start(); },
  replaceToken() { S.menu = false; S.error = ''; S.screen = 'replace'; render(); },
  logout() { if (confirm('Se déconnecter de cet appareil ?')) logout(); },
  undo() { const u = S.toast && S.toast.undo; S.toast = null; clearTimeout(S.toastTimer); if (u) u(); else render(); },
};

root.addEventListener('click', (e) => {
  const el = e.target.closest('[data-act]');
  if (!el || el.tagName === 'FORM' || el.tagName === 'INPUT') return;
  const fn = H[el.dataset.act];
  if (fn) { e.preventDefault(); fn(el, e); }
});
root.addEventListener('submit', (e) => {
  e.preventDefault();
  const fn = H[e.target.dataset.act];
  if (fn) fn(e.target, e);
});
root.addEventListener('input', (e) => {
  const fk = e.target.dataset && e.target.dataset.fk;
  if (fk) S.drafts[fk] = e.target.value;
});
root.addEventListener('change', (e) => {
  if (e.target.dataset && e.target.dataset.act === 'qty') H.qty(e.target);
});
root.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && e.target.dataset && e.target.dataset.act === 'qty') e.target.blur();
});
window.addEventListener('focus', () => poll());
window.addEventListener('pageshow', () => poll());
document.addEventListener('visibilitychange', () => {
  updateWakeLock();
  if (!document.hidden) poll();
});
window.addEventListener('online', () => { if (S.pending.length) scheduleFlush(200); else poll(); });

if ('serviceWorker' in navigator && location.protocol === 'https:') {
  navigator.serviceWorker.register('sw.js').catch(() => {});
}

boot();
