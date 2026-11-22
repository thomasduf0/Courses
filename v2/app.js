'use strict';

/* =====================================================================
   Nos courses — liste de courses partagée Thomas / Mickaël
   Version Supabase : la liste est dans une base Supabase (une ligne par
   produit), mise à jour en direct chez l'autre. Seuls les deux comptes
   du foyer y ont accès (règles d'accès côté base).
   ===================================================================== */

const SUPABASE_URL = 'https://gequwhcsfyykccczwndl.supabase.co';
const SUPABASE_KEY = 'sb_publishable_A9Nvd0yZv_Am5nz0mn_j8A_a-fI1G8L'; // clé publique, faite pour être dans le site
// Ancienne liste (chiffrée dans le dépôt GitHub) : seulement pour l'importer une fois
const OLD = { owner: 'thomasduf0', repo: 'Courses', branch: 'main', config: 'config/acces.json', data: 'data/liste.enc.json' };
const USERS = {
  thomas: { name: 'Thomas', color: '#2f6f4f' },
  mickael: { name: 'Mickaël', color: '#c4553b' },
};
const ITER = 310000;
const POLL_MS = 30000; // filet de sécurité : le temps réel fait le gros du travail
const LS = {
  cache: 'courses2.cache',
  emails: 'courses2.emails',
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
const clone = (o) => JSON.parse(JSON.stringify(o));
const uid = () => (crypto.randomUUID ? crypto.randomUUID().replace(/-/g, '') : Date.now().toString(36) + Math.random().toString(36).slice(2)).slice(0, 16);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const norm = (s) => String(s).normalize('NFD').replace(/[̀-ͯ]/g, '').toLowerCase().trim();
const byName = (a, b) => a.name.localeCompare(b.name, 'fr', { sensitivity: 'base' });
const lsGet = (k, d) => { try { const v = localStorage.getItem(k); return v == null ? d : JSON.parse(v); } catch { return d; } };
const lsSet = (k, v) => { try { v == null ? localStorage.removeItem(k) : localStorage.setItem(k, JSON.stringify(v)); } catch { /* stockage indisponible */ } };

/* ---------- déchiffrement de l'ancienne liste (import) ---------- */
function fromB64(s) {
  const bin = atob(s);
  const b = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) b[i] = bin.charCodeAt(i);
  return b;
}
async function passwordKey(password, salt, iterations = ITER) {
  const base = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
}
const importListKey = (b64) => crypto.subtle.importKey('raw', fromB64(b64), 'AES-GCM', false, ['decrypt']);
async function unseal(key, box) {
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromB64(box.iv) }, key, fromB64(box.ct));
  return dec.decode(pt);
}
async function oldFile(path) {
  // API GitHub (toujours à jour), sinon copie brute
  try {
    const r = await fetch(`https://api.github.com/repos/${OLD.owner}/${OLD.repo}/contents/${path}?ref=${OLD.branch}`, { cache: 'no-store', headers: { Accept: 'application/vnd.github.raw+json' } });
    if (r.ok) return r.json();
  } catch { /* on tente la copie brute */ }
  const r = await fetch(`https://raw.githubusercontent.com/${OLD.owner}/${OLD.repo}/${OLD.branch}/${path}?t=${Date.now()}`, { cache: 'no-store' });
  if (!r.ok) throw new Error('Ancienne liste introuvable (' + r.status + ').');
  return r.json();
}

/* ---------- Supabase ---------- */
const sb = window.supabase.createClient(SUPABASE_URL, SUPABASE_KEY, {
  auth: { persistSession: true, autoRefreshToken: true, detectSessionInUrl: true },
});
const isNetworkError = (e) => !navigator.onLine || !e || !e.code || /fetch|network|load failed/i.test(e.message || '');
const isAuthError = (e) => e && (e.status === 401 || /^PGRST3/.test(e.code || '') || /JWT/i.test(e.message || ''));

// Lignes de la base → état affiché
function rowsToState(cats, prods, card) {
  const st = {
    categories: [...cats]
      .sort((a, b) => a.position - b.position || a.name.localeCompare(b.name, 'fr'))
      .map((c) => ({ id: c.id, name: c.name, emoji: c.emoji, items: [] })),
  };
  const byId = new Map(st.categories.map((c) => [c.id, c]));
  for (const p of prods) {
    const c = byId.get(p.category_id);
    if (c) c.items.push({ id: p.id, name: p.name, qty: p.qty || '', needed: p.needed, inCart: p.in_cart, oos: p.oos, by: p.added_by, at: p.added_at == null ? null : Number(p.added_at) });
  }
  if (card) st.card = { balance: Number(card.balance), at: Number(card.at), by: card.by };
  return st;
}
async function fetchAll() {
  const [c, p, k] = await Promise.all([
    sb.from('categories').select('*'),
    sb.from('produits').select('*'),
    sb.from('carte').select('*').maybeSingle(),
  ]);
  for (const r of [c, p, k]) if (r.error) throw r.error;
  return rowsToState(c.data, p.data, k.data);
}

// Champs d'un produit dans l'appli → colonnes de la base
const FIELDS = { name: 'name', qty: 'qty', needed: 'needed', inCart: 'in_cart', oos: 'oos', by: 'added_by', at: 'added_at' };
const BOOL = new Set(['needed', 'inCart', 'oos']);
const val = (k, v) => (BOOL.has(k) ? !!v : k === 'qty' ? (v || '') : v ?? null);
const itemRow = (it, cat) => {
  const r = { id: it.id, category_id: cat };
  for (const [k, col] of Object.entries(FIELDS)) r[col] = val(k, it[k]);
  return r;
};

// Compare deux états et en déduit les écritures minimales (champ par champ)
function diff(a, b) {
  const w = { upCats: [], delCats: [], insItems: [], updItems: [], delItems: [], card: null };
  const ac = new Map(a.categories.map((c, i) => [c.id, { c, i }]));
  const bc = new Map(b.categories.map((c, i) => [c.id, { c, i }]));
  for (const [id, { c, i }] of bc) {
    const o = ac.get(id);
    if (!o || o.c.name !== c.name || (o.c.emoji || null) !== (c.emoji || null) || o.i !== i) w.upCats.push({ id, name: c.name, emoji: c.emoji || null, position: i });
  }
  for (const id of ac.keys()) if (!bc.has(id)) w.delCats.push(id);
  const index = (st) => { const m = new Map(); for (const c of st.categories) for (const it of c.items) m.set(it.id, { it, cat: c.id }); return m; };
  const ai = index(a), bi = index(b);
  for (const [id, { it, cat }] of bi) {
    const o = ai.get(id);
    if (!o) { w.insItems.push(itemRow(it, cat)); continue; }
    const patch = {};
    for (const [k, col] of Object.entries(FIELDS)) if (val(k, o.it[k]) !== val(k, it[k])) patch[col] = val(k, it[k]);
    if (o.cat !== cat) patch.category_id = cat;
    if (Object.keys(patch).length) w.updItems.push({ id, patch });
  }
  for (const [id, { cat }] of ai) if (!bi.has(id) && !w.delCats.includes(cat)) w.delItems.push(id);
  if (b.card && JSON.stringify(a.card || null) !== JSON.stringify(b.card)) w.card = { id: 1, balance: b.card.balance, at: b.card.at, by: b.card.by || null };
  return w;
}
async function write(w) {
  const ok = (r) => { if (r.error) throw r.error; };
  const now = new Date().toISOString();
  if (w.upCats.length) ok(await sb.from('categories').upsert(w.upCats.map((c) => ({ ...c, updated_at: now }))));
  if (w.insItems.length) ok(await sb.from('produits').upsert(w.insItems.map((r) => ({ ...r, updated_by: S.user, updated_at: now }))));
  // les mêmes changements sur plusieurs produits partent en une seule requête
  const groups = new Map();
  for (const u of w.updItems) {
    const k = JSON.stringify(u.patch);
    if (!groups.has(k)) groups.set(k, { patch: u.patch, ids: [] });
    groups.get(k).ids.push(u.id);
  }
  for (const g of groups.values()) ok(await sb.from('produits').update({ ...g.patch, updated_by: S.user, updated_at: now }).in('id', g.ids));
  if (w.delItems.length) ok(await sb.from('produits').delete().in('id', w.delItems));
  if (w.delCats.length) ok(await sb.from('categories').delete().in('id', w.delCats));
  if (w.card) ok(await sb.from('carte').upsert(w.card));
}

/* ---------- modèle de données ---------- */
function initialState() {
  return { categories: DEFAULT_CATEGORIES.map(([name, emoji]) => ({ id: uid(), name, emoji, items: [] })) };
}
function findItem(st, id) {
  for (const c of st.categories) {
    const i = c.items.findIndex((x) => x.id === id);
    if (i >= 0) return { cat: c, index: i, item: c.items[i] };
  }
  return null;
}
// Chaque modification est une "opération" : appliquée tout de suite à l'écran,
// gardée sur le téléphone sans réseau, puis traduite en écritures dans la base.
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
    case 'setCard': { st.card = { balance: op.balance, at: op.at, by: op.user }; break; }
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
  screen: 'loading', // loading | login | sent | newpw | notmember | import | main
  user: null, uid: null,
  remote: null,
  pending: [], inflight: [], flushing: false, flushTimer: null,
  needRefetch: false, refetchTimer: null, notify: null, channel: null,
  sync: 'idle', syncErr: '', lastSync: 0,
  mode: lsGet(LS.mode, 'maison'),
  filter: lsGet(LS.filter, 'tout'),
  collapsed: new Set(lsGet(LS.collapsed, [])),
  editing: new Set(),
  drafts: {},
  menu: false, cardSheet: null, toast: null, toastTimer: null,
  loginUser: null, signup: false, info: '', error: '', busy: false,
  pollTimer: null, wake: null,
};

function view() {
  if (!S.remote) return null;
  const st = clone(S.remote);
  for (const op of [...S.inflight, ...S.pending]) applyOp(st, op);
  return st;
}
function saveCache() {
  lsSet(LS.cache, { uid: S.uid, user: S.user, remote: S.remote, pending: [...S.inflight, ...S.pending] });
}

/* ---------- synchronisation ---------- */
function act(op) {
  S.pending.push(op);
  saveCache();
  render();
  scheduleFlush(150);
}
function scheduleFlush(ms = 150) {
  clearTimeout(S.flushTimer);
  S.flushTimer = setTimeout(flush, ms);
}
async function flush() {
  if (S.flushing || !S.pending.length || !S.user || !S.remote) return;
  S.flushing = true;
  setSync('saving');
  let rejected = false;
  try {
    while (S.pending.length) {
      const op = S.pending[0];
      S.inflight = [op];
      S.pending = S.pending.slice(1);
      const before = clone(S.remote);
      const after = applyOp(clone(before), op);
      try {
        await write(diff(before, after));
        S.remote = after;
      } catch (e) {
        if (isNetworkError(e) || isAuthError(e)) { S.pending = [op, ...S.pending]; S.inflight = []; throw e; }
        console.warn('Modification refusée par la base', op, e);
        rejected = true; // ex. produit ajouté dans une catégorie que l'autre vient de supprimer
      }
      S.inflight = [];
      saveCache();
    }
    S.lastSync = Date.now();
    setSync('ok');
  } catch (e) {
    if (!handleAuthError(e)) setSync('error', e);
    scheduleFlush(6000);
  } finally {
    S.flushing = false;
    saveCache();
    render();
    if (rejected) showToast('Une modification n’a pas pu être enregistrée');
    if (rejected || S.needRefetch) { S.needRefetch = false; scheduleRefetch(50); }
  }
}
function scheduleRefetch(ms = 300) {
  clearTimeout(S.refetchTimer);
  S.refetchTimer = setTimeout(refetch, ms);
}
async function refetch() {
  if (!S.user || S.screen !== 'main') return;
  if (S.flushing || S.pending.length) { S.needRefetch = true; return; }
  try {
    const st = await fetchAll();
    if (S.flushing || S.pending.length) { S.needRefetch = true; return; } // une modification locale est partie entre-temps
    const changed = JSON.stringify(st) !== JSON.stringify(S.remote);
    S.remote = st;
    S.lastSync = Date.now();
    saveCache();
    setSync('ok');
    const from = S.notify; S.notify = null;
    if (!changed) return;
    if (from && USERS[from] && from !== S.user && !S.toast && !S.menu && !S.cardSheet) showToast(`↻ ${USERS[from].name} a modifié la liste`);
    else render();
  } catch (e) {
    if (!handleAuthError(e)) setSync('error', e);
  }
}
function subscribe() {
  if (S.channel) return;
  S.channel = sb.channel('courses')
    .on('postgres_changes', { event: '*', schema: 'public' }, (p) => {
      const row = p.new && Object.keys(p.new).length ? p.new : null;
      const who = row && (row.updated_by || row.by);
      if (who && who !== S.user) S.notify = who;
      scheduleRefetch(250);
    })
    .subscribe((status) => { if (status === 'SUBSCRIBED') scheduleRefetch(50); });
}
async function unsubscribe() {
  if (S.channel) { const c = S.channel; S.channel = null; try { await sb.removeChannel(c); } catch { /* */ } }
}
function handleAuthError(e) {
  if (isAuthError(e)) {
    setSync('error', new Error('Ta session a expiré. Déconnecte-toi puis reconnecte-toi.'));
    return true;
  }
  return false;
}
function setSync(status, err) {
  S.sync = status;
  S.syncErr = err ? (isNetworkError(err) ? 'Pas de réseau : les changements partiront dès le retour de la connexion.' : err.message || String(err)) : '';
  renderSync();
}
function startPolling() {
  clearInterval(S.pollTimer);
  S.pollTimer = setInterval(() => { if (!document.hidden) refetch(); }, POLL_MS);
}
function poll() { if (S.screen === 'main') { if (S.pending.length) scheduleFlush(100); else refetch(); } }

/* ---------- connexion ---------- */
async function boot() {
  render();
  let session = null;
  try { ({ data: { session } } = await sb.auth.getSession()); } catch { /* hors ligne */ }
  if (S.screen === 'newpw') return; // lien « mot de passe oublié »
  if (!session) {
    const cache = lsGet(LS.cache, null);
    S.screen = 'login';
    if (cache && cache.user) S.loginUser = cache.user;
    render();
    return;
  }
  await afterAuth(session);
}
async function afterAuth(session) {
  S.uid = session.user.id;
  S.error = ''; S.info = '';
  const cache = lsGet(LS.cache, null);
  if (cache && cache.uid === S.uid && cache.remote) {
    // affichage immédiat depuis le téléphone, même sans réseau
    S.user = cache.user; S.remote = cache.remote; S.pending = cache.pending || [];
    S.screen = 'main';
    render();
  }
  try {
    const { data, error } = await sb.from('membres').select('user_id,slug');
    if (error) throw error;
    const me = data.find((m) => m.user_id === S.uid);
    if (!me) { S.screen = 'notmember'; render(); return; }
    S.user = me.slug;
  } catch (e) {
    if (S.screen !== 'main') { S.screen = 'login'; S.error = 'Impossible de joindre la base : ' + (e.message || e); render(); return; }
    setSync('error', e);
  }
  await start();
}
async function start() {
  try {
    const st = await fetchAll();
    if (!st.categories.length && !S.pending.length) { S.screen = 'import'; render(); return; }
    if (!S.flushing && !S.pending.length) S.remote = st;
    else if (!S.remote) S.remote = st;
    S.lastSync = Date.now();
    S.screen = 'main';
    saveCache();
    setSync('ok');
  } catch (e) {
    S.screen = 'main';
    if (!handleAuthError(e)) setSync('error', e);
  }
  render();
  subscribe();
  startPolling();
  if (S.pending.length) scheduleFlush(300);
  updateWakeLock();
}
async function signIn(slug, email, password) {
  const { data, error } = await sb.auth.signInWithPassword({ email, password });
  if (error) throw new Error(/invalid/i.test(error.message) ? 'E-mail ou mot de passe incorrect.' : /confirm/i.test(error.message) ? 'Confirme d’abord ton adresse avec le lien reçu par e-mail.' : error.message);
  rememberEmail(slug, email);
  await afterAuth(data.session);
}
async function signUp(slug, email, password) {
  if (password.length < 8) throw new Error('Choisis un mot de passe d’au moins 8 caractères.');
  const { data, error } = await sb.auth.signUp({ email, password, options: { data: { slug }, emailRedirectTo: location.origin + location.pathname } });
  if (error) throw new Error(error.message);
  rememberEmail(slug, email);
  if (data.session) { await afterAuth(data.session); return; }
  S.screen = 'sent';
  S.info = `Un e-mail de confirmation a été envoyé à ${email}. Clique sur le lien, puis reviens ici pour te connecter.`;
}
async function forgot(email) {
  const { error } = await sb.auth.resetPasswordForEmail(email, { redirectTo: location.origin + location.pathname });
  if (error) throw new Error(error.message);
  S.screen = 'sent';
  S.info = `Un lien pour choisir un nouveau mot de passe a été envoyé à ${email}.`;
}
function rememberEmail(slug, email) { const m = lsGet(LS.emails, {}); m[slug] = email; lsSet(LS.emails, m); }
async function logout() {
  clearInterval(S.pollTimer);
  await unsubscribe();
  try { await sb.auth.signOut(); } catch { /* hors ligne */ }
  lsSet(LS.cache, null);
  Object.assign(S, { user: null, uid: null, remote: null, pending: [], inflight: [], menu: false, screen: 'login', error: '', info: '', drafts: {}, editing: new Set() });
  updateWakeLock();
  render();
}
sb.auth.onAuthStateChange((event) => {
  if (event === 'PASSWORD_RECOVERY') { S.screen = 'newpw'; S.error = ''; render(); }
});

/* ---------- première ouverture : reprendre l'ancienne liste ---------- */
async function seed(st) {
  await write(diff({ categories: [] }, { categories: st.categories, card: st.card }));
}
// Récupération sans mot de passe : l'ancienne appli (même adresse) a gardé sa clé sur cet appareil
function deviceOldSession() {
  const sess = lsGet('courses.session', null);
  const cache = lsGet('courses.cache', null);
  return { listKey: sess && sess.listKey, cached: cache && cache.remote && cache.remote.categories ? cache.remote : null };
}
async function importFromDevice() {
  const { listKey, cached } = deviceOldSession();
  let st = null;
  if (listKey) {
    try { st = JSON.parse(await unseal(await importListKey(listKey), await oldFile(OLD.data))); } catch (e) { console.warn('Lecture de la liste en ligne impossible', e); }
  }
  if (!st && cached) {
    st = clone(cached);
    // rejoue les modifications qui n'avaient pas encore été envoyées
    for (const op of (lsGet('courses.cache', {}).pending || [])) applyOp(st, op);
  }
  if (!st) throw new Error('Aucune ancienne liste trouvée sur cet appareil.');
  await seed(st);
  return st.categories.reduce((n, c) => n + c.items.length, 0);
}
async function importOld(password) {
  const cfg = await oldFile(OLD.config);
  const blob = cfg && cfg.users && cfg.users[S.user];
  if (!blob) throw new Error('Pas d’ancien accès pour ' + USERS[S.user].name + '.');
  let secret;
  try {
    secret = JSON.parse(await unseal(await passwordKey(password, fromB64(blob.salt), cfg.iter || ITER), blob));
  } catch {
    throw new Error('Ancien mot de passe incorrect.');
  }
  const box = await oldFile(OLD.data);
  const st = JSON.parse(await unseal(await importListKey(secret.listKey), box));
  await seed(st);
  return st.categories.reduce((n, c) => n + c.items.length, 0);
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
  else if (S.screen === 'login') html = renderLogin();
  else if (S.screen === 'sent') html = renderSent();
  else if (S.screen === 'newpw') html = renderNewPw();
  else if (S.screen === 'notmember') html = renderNotMember();
  else if (S.screen === 'import') html = renderImport();
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

function authShell(title, body) {
  return `
  <div class="auth">
    <div class="auth-card">
      <div class="auth-logo">🧺</div>
      <h1>${title}</h1>
      ${body}
      ${S.error ? `<p class="err">${esc(S.error)}</p>` : ''}
    </div>
  </div>`;
}

function renderLogin() {
  const u = S.loginUser;
  const email = draft('l:email', (lsGet(LS.emails, {})[u]) || '');
  return authShell('Nos courses', `
      <p class="muted">Qui fait la liste ?</p>
      <div class="who-pick">
        ${Object.entries(USERS).map(([id, x]) => `
          <button type="button" class="who-btn ${u === id ? 'on' : ''}" data-act="pickUser" data-id="${id}" style="--c:${x.color}">
            <span class="avatar">${x.name[0]}</span><span>${x.name}</span>
          </button>`).join('')}
      </div>
      ${u ? `
      <form data-act="${S.signup ? 'signup' : 'login'}">
        <label>E-mail de ${USERS[u].name}
          <input name="email" type="email" data-fk="l:email" value="${esc(email)}" required autocomplete="username" autocapitalize="off" spellcheck="false">
        </label>
        <label>${S.signup ? 'Choisis un mot de passe (8 caractères min.)' : 'Mot de passe'}
          <input name="pw" type="password" data-fk="l:pw" value="${esc(draft('l:pw'))}" required autocomplete="${S.signup ? 'new-password' : 'current-password'}" autocapitalize="off">
        </label>
        <button class="btn primary" ${S.busy ? 'disabled' : ''}>${S.busy ? 'Un instant…' : S.signup ? 'Créer mon compte' : 'Entrer'}</button>
        <button type="button" class="btn ghost" data-act="toggleSignup">${S.signup ? 'J’ai déjà un compte' : 'Première fois ? Créer mon compte'}</button>
        ${S.signup ? '' : '<button type="button" class="link" data-act="forgot">Mot de passe oublié</button>'}
      </form>` : ''}`);
}

function renderSent() {
  return authShell('Regarde tes e-mails', `
      <p class="muted">${esc(S.info)}</p>
      <button class="btn primary" data-act="backToLogin">Revenir à la connexion</button>`);
}

function renderNewPw() {
  return authShell('Nouveau mot de passe', `
      <form data-act="newpw">
        <label>Nouveau mot de passe (8 caractères min.)
          <input name="pw" type="password" data-fk="n:pw" value="${esc(draft('n:pw'))}" required autocomplete="new-password" autocapitalize="off">
        </label>
        <button class="btn primary" ${S.busy ? 'disabled' : ''}>${S.busy ? 'Un instant…' : 'Enregistrer'}</button>
      </form>`);
}

function renderNotMember() {
  return authShell('Pas d’accès', `
      <p class="muted">Ce compte n’a pas accès à la liste. Les deux places du foyer sont déjà prises, ou le prénom choisi l’était déjà.</p>
      <button class="btn ghost" data-act="logoutNow">Se déconnecter</button>`);
}

function renderImport() {
  const old = deviceOldSession();
  const auto = old.listKey || old.cached;
  return authShell('Bienvenue dans la nouvelle version', `
      <p class="muted">La liste est vide pour l’instant. Récupère l’ancienne liste avec toutes ses catégories et ses produits.</p>
      ${auto ? `<button class="btn primary" data-act="importDevice" ${S.busy ? 'disabled' : ''}>${S.busy ? 'Import en cours…' : 'Récupérer l’ancienne liste (sans mot de passe)'}</button>
      <p class="muted">Ou avec ton ancien mot de passe :</p>` : `<p class="muted">L’ancienne appli n’est pas ouverte sur cet appareil : utilise ton <b>ancien</b> mot de passe, ou ouvre cette page sur le téléphone où l’ancienne appli est connectée.</p>`}
      <form data-act="importOld">
        <label>Ancien mot de passe de ${USERS[S.user].name}
          <input name="pw" type="password" data-fk="i:pw" value="${esc(draft('i:pw'))}" required autocomplete="off" autocapitalize="off">
        </label>
        <button class="btn ${auto ? 'ghost' : 'primary'}" ${S.busy ? 'disabled' : ''}>Récupérer avec l’ancien mot de passe</button>
      </form>
      <button class="btn ghost" data-act="seedDefault" ${S.busy ? 'disabled' : ''}>Partir d’une liste vide</button>`);
}

async function authTask(fn) {
  if (S.busy) return;
  S.busy = true; S.error = ''; render();
  try {
    await fn();
    for (const k of Object.keys(S.drafts)) if (/^[lni]:pw$/.test(k)) delete S.drafts[k];
  } catch (e) { S.error = e.message || String(e); }
  S.busy = false; render();
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
  pickUser(b) { S.loginUser = b.dataset.id; S.error = ''; delete S.drafts['l:email']; render(); },
  toggleSignup() { S.signup = !S.signup; S.error = ''; render(); },
  backToLogin() { S.screen = 'login'; S.signup = false; S.error = ''; render(); },
  async login(f) { await authTask(() => signIn(S.loginUser, f.email.value.trim(), f.pw.value)); },
  async signup(f) { await authTask(() => signUp(S.loginUser, f.email.value.trim(), f.pw.value)); },
  async forgot() {
    const email = (draft('l:email', lsGet(LS.emails, {})[S.loginUser] || '') || '').trim();
    if (!email) { S.error = 'Saisis d’abord ton e-mail.'; render(); return; }
    await authTask(() => forgot(email));
  },
  async newpw(f) {
    await authTask(async () => {
      if (f.pw.value.length < 8) throw new Error('Au moins 8 caractères.');
      const { data, error } = await sb.auth.updateUser({ password: f.pw.value });
      if (error) throw new Error(error.message);
      history.replaceState(null, '', location.pathname);
      showToast('Mot de passe changé');
      const { data: { session } } = await sb.auth.getSession();
      if (session) await afterAuth(session); else S.screen = 'login';
      return data;
    });
  },
  async importOld(f) {
    await authTask(async () => {
      const n = await importOld(f.pw.value);
      await start();
      showToast(`Ancienne liste récupérée : ${n} produit${n > 1 ? 's' : ''}`);
    });
  },
  async importDevice() {
    await authTask(async () => {
      const n = await importFromDevice();
      await start();
      showToast(`Ancienne liste récupérée : ${n} produit${n > 1 ? 's' : ''}`);
    });
  },
  async seedDefault() {
    if (!confirm('Partir d’une liste vide (catégories de base) ?')) return;
    await authTask(async () => { await seed(initialState()); await start(); });
  },
  logoutNow() { logout(); },
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
  async refresh() { S.menu = false; render(); await refetch(); showToast('Liste à jour'); },
  retry() { start(); },
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
  navigator.serviceWorker.register('sw.js', { scope: './' }).catch(() => {});
}

boot();
