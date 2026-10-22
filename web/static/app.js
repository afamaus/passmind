'use strict';

// ---------- Hilfsfunktionen ----------

const $ = (id) => document.getElementById(id);

async function api(method, path, body) {
  const opts = { method, headers: { 'X-PS-Request': '1' }, credentials: 'same-origin' };
  if (body !== undefined) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  const res = await fetch('api/' + path, opts);
  const type = res.headers.get('Content-Type') || '';
  if (!res.ok) {
    let msg = 'Fehler ' + res.status;
    if (type.includes('json')) msg = (await res.json()).error || msg;
    if (res.status === 423) { showLocked(msg === 'Tresor ist gesperrt' ? '' : msg); }
    throw new Error(msg);
  }
  if (type.includes('json')) return res.json();
  return res;
}

function el(tag, attrs = {}, ...children) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'class') e.className = v;
    else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
    else if (k === 'dataset') Object.assign(e.dataset, v);
    else e.setAttribute(k, v);
  }
  for (const c of children.flat()) {
    if (c == null) continue;
    e.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return e;
}

function toast(msg, isError = false, ms = 3000) {
  const t = el('div', { class: 'toast' + (isError ? ' error' : '') }, msg);
  $('toasts').append(t);
  setTimeout(() => t.remove(), ms);
  return t;
}

function readFileB64(input) {
  const f = input.files && input.files[0];
  if (!f) return Promise.resolve('');
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onload = () => resolve(r.result.split(',')[1] || '');
    r.onerror = () => reject(new Error('Datei konnte nicht gelesen werden'));
    r.readAsDataURL(f);
  });
}

function readFileText(input) {
  const f = input.files && input.files[0];
  if (!f) return Promise.resolve('');
  return f.text();
}

function show(viewId) {
  for (const v of document.querySelectorAll('.view')) v.classList.toggle('hidden', v.id !== viewId);
}

function busy(btn, on) {
  if (!btn) return;
  btn.disabled = on;
}

// Passwortstärke grob über Zeichenvorrat und Länge schätzen.
function strength(pw) {
  if (!pw) return { bits: 0, label: '', color: 'transparent' };
  let pool = 0;
  if (/[a-z]/.test(pw)) pool += 26;
  if (/[A-Z]/.test(pw)) pool += 26;
  if (/[0-9]/.test(pw)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(pw)) pool += 33;
  let bits = pw.length * Math.log2(Math.max(pool, 1));
  if (/^(.)\1+$/.test(pw)) bits = Math.min(bits, 10);
  if (/(passwor|123456|qwert|letmein|admin)/i.test(pw)) bits = Math.min(bits, 20);
  const levels = [
    [28, 'sehr schwach', '#c93a3a'],
    [40, 'schwach', '#e0703a'],
    [60, 'mittel', '#d0a012'],
    [80, 'stark', '#5aa64a'],
    [Infinity, 'sehr stark', '#2e9e5b'],
  ];
  const [, label, color] = levels.find(([max]) => bits < max);
  return { bits: Math.round(bits), label, color };
}

function bindMeter(input, bar, text) {
  const update = () => {
    const s = strength(input.value);
    bar.style.width = Math.min(100, s.bits / 1.2) + '%';
    bar.style.background = s.color;
    text.textContent = s.label ? `Stärke: ${s.label} (~${s.bits} Bit)` : '';
  };
  input.addEventListener('input', update);
  return update;
}

// ---------- Zwischenablage ----------

let clipboardSeconds = 20;
let clipTimer = null;

async function copyText(text, what = 'Text') {
  if (!text) { toast('Nichts zu kopieren'); return; }
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    toast('Kopieren nicht möglich', true);
    return;
  }
  toast(`${what} kopiert, wird in ${clipboardSeconds} s geleert`);
  clearTimeout(clipTimer);
  clipTimer = setTimeout(() => navigator.clipboard.writeText('').catch(() => {}), clipboardSeconds * 1000);
}

document.addEventListener('click', (ev) => {
  const btn = ev.target.closest('[data-copy]');
  if (btn) {
    ev.preventDefault();
    const input = $(btn.dataset.copy);
    copyText(input.value, btn.dataset.copy.includes('password') || btn.dataset.copy === 'gen-result' ? 'Passwort' : 'Text');
  }
  const close = ev.target.closest('[data-close]');
  if (close) close.closest('dialog').close();
});

// ---------- Start ----------

let status = {};

async function init() {
  try {
    status = await api('GET', 'status');
  } catch (e) {
    document.body.textContent = e.message;
    return;
  }
  migrateTheme();
  if (!status.exists) startSetup();
  else if (!status.unlocked) showLocked();
  else await openMain();
}

// ---------- Einrichtungsassistent ----------
// 1 Tresor (neu/vorhanden) · 2 Speicherort und Verbindungsart · 3 Superuser anlegen bzw. anmelden
// · 4 Design · 5 Benutzer und AD (nur Admins)

let setupState = {};
let wizard = { kind: 'new', pending: false };   // pending: nach der Anmeldung mit Schritt 4 weitermachen

const STEP_IDS = { 1: ['wz-1'], 2: ['wz-2'], 3: ['setup-step1', 'setup-step2', 'setup-step3'], 4: ['wz-4'], 5: ['wz-5'] };

function setStep(n, sub = 'setup-step1') {
  for (const li of document.querySelectorAll('#view-setup .steps li')) {
    const st = Number(li.dataset.step);
    li.classList.toggle('active', st === n);
    li.classList.toggle('done', st < n);
  }
  for (const [k, ids] of Object.entries(STEP_IDS)) {
    for (const id of ids) $(id).classList.toggle('hidden', Number(k) !== n || (n === 3 && id !== sub));
  }
}

function splitPath(p) {
  const i = Math.max(p.lastIndexOf('/'), p.lastIndexOf('\\'));
  return i < 0 ? ['', p] : [p.slice(0, i) || p.slice(0, 1), p.slice(i + 1)];
}

function joinAny(dir, name) {
  const sep = dir.includes('\\') ? '\\' : '/';
  return dir.endsWith(sep) ? dir + name : dir + sep + name;
}

function startSetup(fromUnlock = false) {
  closeAllDialogs();
  show('view-setup');
  restoreUserSections();
  $('setup-missing').classList.toggle('hidden', !status.missingKnown);
  $('wz-conn-error').classList.toggle('hidden', !status.connError);
  $('wz-conn-error').textContent = status.connError || '';
  $('wz-cancel-wrap').classList.toggle('hidden', !fromUnlock);
  const others = status.recent || [];
  $('wz-recent').classList.toggle('hidden', others.length === 0);
  $('wz-recent').replaceChildren(el('div', { class: 'label' }, 'Zuletzt verwendet:'),
    ...others.map((p) => el('a', { href: '#', onclick: (ev) => { ev.preventDefault(); selectVault(p); } }, p)));
  // Speicherort und Verbindung mit dem aktuellen Stand vorbelegen.
  const [dir, name] = splitPath(status.path || '');
  $('wz-dir').value = dir;
  $('wz-name').value = name || 'passmind.vault';
  const conn = status.connection || {};
  setMode(conn.mode === 'network' ? 'network' : 'default');
  $('wz-net-user').value = conn.user || '';
  $('wz-net-pw').value = '';
  setStep(1);
}

function setMode(mode) {
  for (const r of document.querySelectorAll('input[name=wz-mode]')) r.checked = r.value === mode;
  const supported = (status.connection || {}).supported;
  $('wz-net').classList.toggle('hidden', mode !== 'network' || !supported);
  $('wz-net-unsupported').classList.toggle('hidden', mode !== 'network' || supported);
}
for (const r of document.querySelectorAll('input[name=wz-mode]')) r.addEventListener('change', () => setMode(r.value));

const wzMode = () => document.querySelector('input[name=wz-mode]:checked').value;

for (const b of document.querySelectorAll('#wz-1 .choice')) {
  b.addEventListener('click', () => {
    wizard.kind = b.dataset.kind;
    $('wz-step3-label').textContent = wizard.kind === 'new' ? 'Superuser' : 'Anmelden';
    $('wz-2-next').textContent = wizard.kind === 'new' ? 'Weiter' : 'Tresor öffnen';
    $('wz-error2').textContent = '';
    setStep(2);
    $('wz-dir').focus();
  });
}
for (const b of document.querySelectorAll('[data-wz-back]')) b.addEventListener('click', () => setStep(Number(b.dataset.wzBack)));
$('wz-cancel').addEventListener('click', () => showLocked());

// Bei Netzwerk-Anmeldung zuerst die Freigabe verbinden, sonst lässt sie sich nicht durchsuchen.
async function connectIfNeeded() {
  if (wzMode() !== 'network') return;
  if (!(status.connection || {}).supported) throw new Error($('wz-net-unsupported').textContent);
  await api('POST', 'connect', { path: $('wz-dir').value.trim(), user: $('wz-net-user').value.trim(), password: $('wz-net-pw').value });
  $('wz-net-pw').value = '';
  status.connection = { ...status.connection, mode: 'network', user: $('wz-net-user').value.trim() };
}

$('wz-browse').addEventListener('click', async () => {
  $('wz-error2').textContent = '';
  try {
    if (wzMode() === 'network' && $('wz-net-pw').value) await connectIfNeeded();
    openBrowser('pick', $('wz-dir').value.trim());
  } catch (e) { $('wz-error2').textContent = e.message; }
});

$('wz-2').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const btn = $('wz-2-next');
  busy(btn, true);
  $('wz-error2').textContent = '';
  try {
    const dir = $('wz-dir').value.trim();
    if (wzMode() === 'network' && (status.connection || {}).mode !== 'network' && !$('wz-net-pw').value) {
      throw new Error('Bitte Benutzer und Passwort für die Freigabe eingeben.');
    }
    if ($('wz-net-pw').value) await connectIfNeeded();
    const path = joinAny(dir, $('wz-name').value.trim() || 'passmind.vault');
    await api('POST', 'vault/select', { path, mode: wzMode(), expect: wizard.kind });
    status = await api('GET', 'status');
    if (wizard.kind === 'new') {
      $('setup-path').textContent = status.path;
      setStep(3, 'setup-step1');
      $('setup-user').focus();
    } else {
      wizard.pending = true;
      showLocked();
    }
  } catch (e) {
    $('wz-error2').textContent = e.message;
  } finally {
    busy(btn, false);
  }
});

bindMeter($('setup-pw'), $('setup-meter'), $('setup-meter-text'));

$('setup-step1').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const pw = $('setup-pw').value, pw2 = $('setup-pw2').value, user = $('setup-user').value.trim();
  $('setup-error1').textContent = '';
  if (!user) { $('setup-error1').textContent = 'Bitte einen Benutzernamen angeben.'; return; }
  if (pw.length < 10) { $('setup-error1').textContent = 'Mindestens 10 Zeichen.'; return; }
  if (pw !== pw2) { $('setup-error1').textContent = 'Die Passwörter stimmen nicht überein.'; return; }
  try {
    setupState = { user, password: pw, keyFile: await readFileB64($('setup-keyfile')) };
    const t = await api('POST', 'setup/totp?user=' + encodeURIComponent(user));
    $('setup-qr').src = t.qr;
    $('setup-secret').textContent = t.secret.replace(/(.{4})/g, '$1 ').trim();
    setStep(3, 'setup-step2');
    $('setup-code').focus();
  } catch (e) {
    $('setup-error1').textContent = e.message;
  }
});

$('setup-back').addEventListener('click', () => setStep(3, 'setup-step1'));

$('setup-step2').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const btn = ev.submitter;
  busy(btn, true);
  $('setup-error2').textContent = '';
  try {
    const r = await api('POST', 'setup', { ...setupState, code: $('setup-code').value });
    rememberUser(setupState.user);
    setupState = { codes: r.recoveryCodes };
    $('setup-recovery').replaceChildren(...r.recoveryCodes.map((c) => el('li', {}, c)));
    setStep(3, 'setup-step3');
  } catch (e) {
    $('setup-error2').textContent = e.message;
  } finally {
    busy(btn, false);
  }
});

$('setup-copy-codes').addEventListener('click', () => {
  navigator.clipboard.writeText(setupState.codes.join('\n')).then(() => toast('Codes kopiert'));
});

$('setup-done').addEventListener('click', async () => {
  setupState = {};
  $('setup-pw').value = $('setup-pw2').value = $('setup-code').value = '';
  await reload();
  showDesignStep();
});

function showDesignStep() {
  show('view-setup');
  markTheme();
  setStep(4);
}

function markTheme() {
  const cur = document.documentElement.dataset.theme === 'light' ? 'light' : 'dark';
  for (const b of document.querySelectorAll('.theme-choice')) b.classList.toggle('active', b.dataset.themeChoice === cur);
}
for (const b of document.querySelectorAll('.theme-choice')) {
  b.addEventListener('click', () => { applyTheme(b.dataset.themeChoice); markTheme(); });
}

$('wz-4-next').addEventListener('click', () => {
  if (data.role !== 'admin') { finishWizard(); return; }
  // Benutzerverwaltung und AD-Einstellungen aus den Einstellungen hierher holen.
  prepareAdminSections();
  $('wz-users-slot').append($('users-section'), $('ad-section'));
  setStep(5);
});

$('wz-finish').addEventListener('click', finishWizard);

function finishWizard() {
  restoreUserSections();
  wizard.pending = false;
  show('view-main');
  $('search').focus();
}

// Die beiden Abschnitte gehören eigentlich in den Einstellungsdialog.
function restoreUserSections() {
  const anchor = $('cred-form');
  if ($('users-section').parentElement !== anchor.parentElement) anchor.before($('users-section'), $('ad-section'));
}

// ---------- Entsperren ----------

let useRecovery = false;

function lastUser() {
  try { return localStorage.getItem('pm-user') || ''; } catch { return ''; }
}
function rememberUser(u) {
  try { localStorage.setItem('pm-user', u); } catch { /* egal */ }
}

function updateKeyFileField() {
  const login = status.login || {};
  const u = $('unlock-user').value.trim().toLowerCase();
  const needs = login.legacy ? login.keyFileNeeded
    : (login.keyFileUsers || []).some((x) => x.toLowerCase() === u);
  $('unlock-keyfile-wrap').classList.toggle('hidden', !needs);
}
$('unlock-user').addEventListener('input', updateKeyFileField);

async function showLocked(message) {
  closeAllDialogs();
  try { status = await api('GET', 'status'); } catch { /* bleibt beim alten Status */ }
  if (!status.exists) { startSetup(); return; }
  show('view-unlock');
  $('unlock-path').textContent = status.path;
  $('unlock-error').textContent = message || '';
  const others = (status.recent || []).filter((p) => p !== status.path);
  $('unlock-recent').classList.toggle('hidden', others.length === 0);
  $('unlock-recent').replaceChildren(el('div', { class: 'label' }, 'Zuletzt verwendet:'),
    ...others.map((p) => el('a', { href: '#', onclick: (ev) => { ev.preventDefault(); selectVault(p); } }, p)));
  const login = status.login || { users: [] };
  const users = login.users || [];
  $('unlock-legacy').classList.toggle('hidden', !login.legacy);
  $('unlock-user-wrap').classList.toggle('hidden', !!login.legacy);
  $('unlock-user').required = !login.legacy;
  $('unlock-users').replaceChildren(...users.map((u) => el('option', { value: u })));
  $('unlock-ad-hint').classList.toggle('hidden', !login.adDomain);
  $('unlock-ad-hint').textContent = login.adDomain ? `Lokaler Benutzer oder AD-Konto, z. B. name oder name@${login.adDomain}` : '';
  const last = lastUser();
  const known = users.find((u) => u.toLowerCase() === last.toLowerCase());
  $('unlock-user').value = known || (users.length === 1 ? users[0] : '');
  updateKeyFileField();
  $('unlock-pw').value = '';
  $('unlock-code').value = '';
  $('unlock-recovery').value = '';
  ($('unlock-user').value || login.legacy ? $('unlock-pw') : $('unlock-user')).focus();
  if (status.error) $('unlock-error').textContent = status.error;
  $('unlock-conn-error').classList.toggle('hidden', !status.connError);
  $('unlock-conn-error').textContent = status.connError || '';
}

$('unlock-toggle-recovery').addEventListener('click', (ev) => {
  ev.preventDefault();
  useRecovery = !useRecovery;
  $('unlock-code-wrap').classList.toggle('hidden', useRecovery);
  $('unlock-recovery-wrap').classList.toggle('hidden', !useRecovery);
  ev.target.textContent = useRecovery ? 'Code aus der Authenticator-App verwenden' : 'Handy nicht zur Hand? Wiederherstellungscode verwenden';
});

$('unlock-form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const btn = $('unlock-btn');
  busy(btn, true);
  btn.textContent = 'Prüfe …';
  $('unlock-error').textContent = '';
  try {
    const user = $('unlock-user').value.trim();
    const body = { user, password: $('unlock-pw').value, keyFile: await readFileB64($('unlock-keyfile')) };
    if (useRecovery) body.recoveryCode = $('unlock-recovery').value; else body.code = $('unlock-code').value;
    const r = await api('POST', 'unlock', body);
    $('unlock-pw').value = '';
    if (r.enroll) { rememberUser(r.user); startEnroll(r); return; }
    if (user) rememberUser(user);
    await openMain();
    if (r.recoveryUsed) {
      toast(`Wiederherstellungscode verbraucht. Noch ${r.recoveryRemaining} übrig. Richte den Authenticator in den Einstellungen neu ein.`, false, 8000);
    }
  } catch (e) {
    $('unlock-error').textContent = e.message;
  } finally {
    busy(btn, false);
    btn.textContent = 'Entsperren';
  }
});

// ---------- Erste Anmeldung ----------

let enrollState = {};

function startEnroll(r) {
  enrollState = { mustChange: r.mustChange };
  show('view-enroll');
  $('enroll-user').textContent = r.user;
  $('enroll-pw-wrap').classList.toggle('hidden', !r.mustChange);
  $('enroll-qr').src = r.qr;
  $('enroll-secret').textContent = r.secret.replace(/(.{4})/g, '$1 ').trim();
  $('enroll-form').classList.remove('hidden');
  $('enroll-done').classList.add('hidden');
  $('enroll-error').textContent = '';
  for (const id of ['enroll-pw', 'enroll-pw2', 'enroll-code']) $(id).value = '';
  (r.mustChange ? $('enroll-pw') : $('enroll-code')).focus();
}

bindMeter($('enroll-pw'), $('enroll-meter'), $('enroll-meter-text'));

$('enroll-form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  $('enroll-error').textContent = '';
  const pw = $('enroll-pw').value;
  if (enrollState.mustChange) {
    if (pw.length < 10) { $('enroll-error').textContent = 'Das neue Passwort braucht mindestens 10 Zeichen.'; return; }
    if (pw !== $('enroll-pw2').value) { $('enroll-error').textContent = 'Die Passwörter stimmen nicht überein.'; return; }
  }
  const btn = ev.submitter;
  busy(btn, true);
  try {
    const r = await api('POST', 'enroll', { newPassword: enrollState.mustChange ? pw : '', code: $('enroll-code').value });
    enrollState = { codes: r.recoveryCodes };
    $('enroll-pw').value = $('enroll-pw2').value = '';
    $('enroll-recovery').replaceChildren(...r.recoveryCodes.map((c) => el('li', {}, c)));
    $('enroll-form').classList.add('hidden');
    $('enroll-done').classList.remove('hidden');
  } catch (e) {
    $('enroll-error').textContent = e.message;
  } finally {
    busy(btn, false);
  }
});

$('enroll-cancel').addEventListener('click', async () => {
  await api('POST', 'lock').catch(() => {});
  enrollState = {};
  showLocked();
});

$('enroll-copy-codes').addEventListener('click', () => {
  navigator.clipboard.writeText(enrollState.codes.join('\n')).then(() => toast('Codes kopiert'));
});

$('enroll-finish').addEventListener('click', () => {
  enrollState = {};
  openMain();
});

// ---------- Hauptansicht ----------

let data = { folders: [], entries: [], settings: {} };
let currentFolder = '';   // '' = alle Einträge
let searchTerm = '';
const selected = new Set();   // ausgewählte Einträge (Auswahlkästchen)

async function openMain() {
  await reload();
  if (wizard.pending) { showDesignStep(); return; }
  show('view-main');
  $('search').focus();
}

// Der persönliche Tresor erscheint als eigener (roter) Ordner. Seine oberste Ebene bekommt in der
// Oberfläche die Kennung PERSONAL; zum Server geht sie als folderId "" mit personal: true.
const PERSONAL = '@personal';

function isPersonal(id) {
  return id === PERSONAL || !!data.folders.find((f) => f.id === id && f.personal);
}
function serverFolder(id) { return id === PERSONAL ? '' : id; }

async function reload() {
  data = await api('GET', 'data');
  for (const f of data.folders) if (f.personal && !f.parentId) f.parentId = PERSONAL;
  for (const e of data.entries) if (e.personal && !e.folderId) e.folderId = PERSONAL;
  clipboardSeconds = data.settings.clipboardSeconds || 20;
  $('whoami').textContent = '👤 ' + data.user + (data.ad ? ' · AD' : '') + (data.role === 'admin' ? ' (Admin)' : '');
  if (currentFolder && currentFolder !== PERSONAL && !data.folders.some((f) => f.id === currentFolder)) currentFolder = '';
  if (currentFolder === PERSONAL && !data.personal.available) currentFolder = '';
  $('bulk-folder').replaceChildren();
  renderTree();
  renderEntries();
}

function childrenOf(parentId) {
  return data.folders
    .filter((f) => (f.parentId || '') === parentId)
    .sort((a, b) => a.name.localeCompare(b.name, 'de'));
}

function descendants(id) {
  const out = new Set([id]);
  let grew = true;
  while (grew) {
    grew = false;
    for (const f of data.folders) {
      if (!out.has(f.id) && out.has(f.parentId)) { out.add(f.id); grew = true; }
    }
  }
  return out;
}

function folderPath(id) {
  const parts = [];
  let f = data.folders.find((x) => x.id === id);
  while (f && parts.length < 50) {
    parts.unshift(f.name);
    f = data.folders.find((x) => x.id === f.parentId);
  }
  if (isPersonal(id)) parts.unshift('Persönlich');
  return parts.join(' / ');
}

// Ordnersymbol als SVG, damit es sich einfärben lässt (rot = persönlich).
function folderIcon(cls = '') {
  const ns = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(ns, 'svg');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('class', 'ficon ' + cls);
  svg.setAttribute('aria-hidden', 'true');
  const path = document.createElementNS(ns, 'path');
  path.setAttribute('d', 'M10 4H4a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-8l-2-2z');
  svg.append(path);
  return svg;
}

// ---------- Drag & Drop ----------
// Einträge lassen sich auf einen Ordner ziehen, Ordner auf einen anderen Ordner
// oder auf „Alle Einträge“ (= oberste Ebene).

let dragging = null;   // { kind: 'entry' | 'folder', id }

function startDrag(ev, kind, id, label) {
  dragging = { kind, id };
  ev.dataTransfer.effectAllowed = 'move';
  ev.dataTransfer.setData('text/plain', label);   // ohne Daten starten manche Browser kein Ziehen
  document.body.classList.add('dragging');
}

document.addEventListener('dragend', () => {
  dragging = null;
  document.body.classList.remove('dragging');
  for (const n of document.querySelectorAll('.tree .drop')) n.classList.remove('drop');
});

function canDrop(targetId) {
  if (!dragging) return false;
  if (dragging.kind === 'entry') return targetId !== '';
  // Ordner bleiben in ihrem Bereich (gemeinsam oder persönlich).
  return isPersonal(dragging.id) === isPersonal(targetId) && !descendants(dragging.id).has(targetId);
}

function dropTarget(node, targetId, targetName) {
  node.addEventListener('dragenter', (ev) => { if (canDrop(targetId)) { ev.preventDefault(); node.classList.add('drop'); } });
  node.addEventListener('dragover', (ev) => {
    if (!canDrop(targetId)) return;
    ev.preventDefault();
    ev.dataTransfer.dropEffect = 'move';
    node.classList.add('drop');
  });
  node.addEventListener('dragleave', (ev) => { if (!node.contains(ev.relatedTarget)) node.classList.remove('drop'); });
  node.addEventListener('drop', async (ev) => {
    ev.preventDefault();
    node.classList.remove('drop');
    const d = dragging;
    if (!d || !canDrop(targetId)) return;
    try {
      if (d.kind === 'entry' && selected.has(d.id) && selected.size > 1) {
        await bulkMove([...selected], targetId);
        return;
      }
      if (d.kind === 'entry') {
        const full = await api('GET', 'entries/' + d.id);
        if (full.folderId === serverFolder(targetId) && full.personal === isPersonal(targetId)) return;
        full.folderId = serverFolder(targetId);
        full.personal = isPersonal(targetId);
        await api('POST', 'entries', full);
        toast(`Verschoben nach „${targetName}“`);
      } else {
        const f = data.folders.find((x) => x.id === d.id);
        if (!f || (f.parentId || '') === targetId) return;
        await api('POST', 'folders', { ...f, parentId: serverFolder(targetId), personal: isPersonal(targetId) });
        toast(targetId ? `Ordner „${f.name}“ nach „${targetName}“ verschoben` : `Ordner „${f.name}“ auf oberste Ebene verschoben`);
      }
      await reload();
    } catch (e) { toast(e.message, true); }
  });
}

function folderNode(f) {
  const count = data.entries.filter((e) => descendants(f.id).has(e.folderId)).length;
  const node = el('div', {
    class: 'node' + (currentFolder === f.id ? ' active' : ''),
    draggable: 'true',
    title: 'Einträge oder Ordner hierher ziehen',
    onclick: () => { currentFolder = f.id; selected.clear(); renderTree(); renderEntries(); },
  }, folderIcon(f.personal ? 'personal' : ''), f.name, el('span', { class: 'count' }, count));
  node.addEventListener('dragstart', (ev) => { ev.stopPropagation(); startDrag(ev, 'folder', f.id, f.name); });
  dropTarget(node, f.id, f.name);
  const kids = childrenOf(f.id);
  return el('li', {}, node, kids.length ? el('ul', {}, kids.map(folderNode)) : null);
}

function personalNode() {
  const st = data.personal || {};
  if (!st.available && !st.locked) return null;
  const count = data.entries.filter((e) => e.personal).length;
  const node = el('div', {
    class: 'node personal-root' + (currentFolder === PERSONAL ? ' active' : ''),
    title: st.locked ? 'Gesperrt: bisheriges AD-Passwort nötig' : 'Nur du siehst diese Einträge. Einträge hierher ziehen, um sie privat zu machen.',
    onclick: () => {
      if (st.locked) { openPersonalUnlock(); return; }
      currentFolder = PERSONAL; selected.clear(); renderTree(); renderEntries();
    },
  }, folderIcon('personal'), 'Persönlicher Tresor', el('span', { class: 'count' }, st.locked ? '🔒' : count));
  if (st.available) dropTarget(node, PERSONAL, 'Persönlicher Tresor');
  const kids = st.available ? childrenOf(PERSONAL) : [];
  return el('li', { class: 'personal-li' }, node, kids.length ? el('ul', {}, kids.map(folderNode)) : null);
}

function renderTree() {
  const all = el('div', {
    class: 'node' + (currentFolder === '' ? ' active' : ''),
    onclick: () => { currentFolder = ''; selected.clear(); renderTree(); renderEntries(); },
  }, '🗂 Alle Einträge', el('span', { class: 'count' }, data.entries.filter((e) => !e.personal).length));
  dropTarget(all, '', 'Alle Einträge');
  $('folder-tree').replaceChildren(el('li', {}, all), ...childrenOf('').map(folderNode), personalNode() || '');
  $('list-title').textContent = currentFolder === PERSONAL ? 'Persönlicher Tresor' : currentFolder ? folderPath(currentFolder) : 'Alle Einträge';
  $('list-title').classList.toggle('personal', isPersonal(currentFolder));
  const real = currentFolder && currentFolder !== PERSONAL;
  $('btn-edit-folder').classList.toggle('hidden', !real);
  $('btn-delete-folder').classList.toggle('hidden', !real);
}

function matches(e, term) {
  if (!term) return true;
  const hay = [e.title, e.username, e.url, e.notes, ...(e.tags || [])].join('\n').toLowerCase();
  return term.toLowerCase().split(/\s+/).every((t) => hay.includes(t));
}

function renderEntries() {
  const scope = currentFolder ? descendants(currentFolder) : null;
  const list = data.entries
    .filter((e) => (searchTerm ? true : scope ? scope.has(e.folderId) : !e.personal))
    .filter((e) => matches(e, searchTerm))
    .sort((a, b) => a.title.localeCompare(b.title, 'de'));
  const rows = list.map((e) => {
    const box = el('input', { type: 'checkbox', 'aria-label': 'Auswählen' });
    box.checked = selected.has(e.id);
    box.addEventListener('click', (ev) => ev.stopPropagation());
    box.addEventListener('change', () => {
      if (box.checked) selected.add(e.id); else selected.delete(e.id);
      tr.classList.toggle('selected', box.checked);
      updateBulkBar();
    });
    const tr = el('tr', { class: selected.has(e.id) ? 'selected' : '', draggable: 'true', title: 'Zum Verschieben auf einen Ordner links ziehen', onclick: () => openEntry(e.id) },
      el('td', { class: 'sel', onclick: (ev) => { ev.stopPropagation(); if (ev.target !== box) box.click(); } }, box),
      el('td', { class: 'title' }, el('span', { class: 'grip', 'aria-hidden': 'true' }, '⠿'),
        e.personal ? el('span', { class: 'plock', title: 'Persönlicher Tresor, nur für dich sichtbar' }, '🔒') : null, e.title,
        (searchTerm || !currentFolder) && e.folderId ? el('span', { class: 'folder-hint' }, folderPath(e.folderId)) : null),
      el('td', {}, e.username),
      passwordCell(e.id),
      el('td', { class: 'url hide-sm' }, e.url),
      el('td', { class: 'hide-sm' }, (e.tags || []).map((t) => el('span', { class: 'tag' }, t))),
      el('td', { class: 'actions' },
        el('button', { class: 'icon', title: 'Benutzer kopieren', onclick: (ev) => { ev.stopPropagation(); copyText(e.username, 'Benutzername'); } }, '👤'),
        el('button', { class: 'icon', title: 'Passwort kopieren', onclick: (ev) => { ev.stopPropagation(); copyPassword(e.id); } }, '🔑'),
        e.url ? el('button', { class: 'icon', title: 'URL öffnen', onclick: (ev) => { ev.stopPropagation(); openUrl(e.url); } }, '↗') : null,
        el('button', { class: 'icon del', title: 'Eintrag löschen', onclick: (ev) => { ev.stopPropagation(); deleteEntry(e.id, e.title); } }, '🗑'),
      ));
    tr.addEventListener('dragstart', (ev) => startDrag(ev, 'entry', e.id, selected.has(e.id) && selected.size > 1 ? `${selected.size} Einträge` : e.title));
    return tr;
  });
  visibleIds = list.map((e) => e.id);
  $('entry-rows').replaceChildren(...rows);
  updateBulkBar();
  $('empty-hint').classList.toggle('hidden', rows.length > 0);
  $('empty-hint').textContent = searchTerm ? 'Keine Treffer.' : 'Keine Einträge. Lege mit „Neuer Eintrag“ den ersten an.';
}

// ---------- Mehrfachauswahl ----------

let visibleIds = [];

function updateBulkBar() {
  // Nur noch vorhandene Einträge in der Auswahl behalten.
  for (const id of selected) if (!data.entries.some((e) => e.id === id)) selected.delete(id);
  const n = selected.size;
  $('bulk-bar').classList.toggle('hidden', n === 0);
  $('bulk-count').textContent = n === 1 ? '1 Eintrag ausgewählt' : `${n} Einträge ausgewählt`;
  const visibleSel = visibleIds.filter((id) => selected.has(id)).length;
  $('sel-all').checked = visibleIds.length > 0 && visibleSel === visibleIds.length;
  $('sel-all').indeterminate = visibleSel > 0 && visibleSel < visibleIds.length;
  if (n > 0 && !$('bulk-folder').options.length) {
    fillFolderSelect($('bulk-folder'), currentFolder, { allowRoot: true });
  }
}

$('sel-all').addEventListener('change', (ev) => {
  for (const id of visibleIds) {
    if (ev.target.checked) selected.add(id); else selected.delete(id);
  }
  renderEntries();
});

$('bulk-clear').addEventListener('click', () => { selected.clear(); renderEntries(); });

async function bulkMove(ids, folderId) {
  const r = await api('POST', 'entries/bulk', { action: 'move', ids, folderId: serverFolder(folderId), personal: isPersonal(folderId) });
  const name = folderId === PERSONAL ? 'Persönlicher Tresor' : folderId ? data.folders.find((f) => f.id === folderId)?.name : 'kein Ordner';
  toast(`${r.count} ${r.count === 1 ? 'Eintrag' : 'Einträge'} verschoben nach „${name}“`);
  selected.clear();
  await reload();
}

$('bulk-move').addEventListener('click', async () => {
  try { await bulkMove([...selected], $('bulk-folder').value); } catch (e) { toast(e.message, true); }
});

$('bulk-delete').addEventListener('click', async () => {
  const n = selected.size;
  if (!confirm(`${n} ${n === 1 ? 'Eintrag' : 'Einträge'} wirklich löschen?`)) return;
  try {
    const r = await api('POST', 'entries/bulk', { action: 'delete', ids: [...selected] });
    toast(`${r.count} ${r.count === 1 ? 'Eintrag' : 'Einträge'} gelöscht`);
    selected.clear();
    await reload();
  } catch (e) { toast(e.message, true); }
});

const MASK = '••••••••';

// Passwort in der Liste: verdeckt, per Auge für 5 Sekunden sichtbar.
function passwordCell(id) {
  const text = el('span', { class: 'pw' }, MASK);
  let timer = null;
  const eye = el('button', {
    class: 'icon', title: 'Passwort 5 Sekunden anzeigen',
    onclick: async (ev) => {
      ev.stopPropagation();
      if (timer) { clearTimeout(timer); timer = null; text.textContent = MASK; text.classList.remove('shown'); return; }
      try {
        const e = await api('GET', 'entries/' + id);
        text.textContent = e.password || '(leer)';
        text.classList.add('shown');
        timer = setTimeout(() => { text.textContent = MASK; text.classList.remove('shown'); timer = null; }, 5000);
      } catch (err) { toast(err.message, true); }
    },
  }, '👁');
  return el('td', { class: 'pw-cell' }, text, eye);
}

async function deleteEntry(id, title) {
  if (!confirm(`Eintrag „${title}“ wirklich löschen?`)) return;
  try {
    await api('DELETE', 'entries/' + id);
    toast('Gelöscht');
    await reload();
  } catch (e) { toast(e.message, true); }
}

async function copyPassword(id) {
  try {
    const e = await api('GET', 'entries/' + id);
    copyText(e.password, 'Passwort');
  } catch (err) { toast(err.message, true); }
}

function openUrl(url) {
  if (!/^[a-z][a-z0-9+.-]*:/i.test(url)) url = 'https://' + url;
  if (!/^https?:/i.test(url)) { toast('Nur http(s)-Adressen werden geöffnet', true); return; }
  window.open(url, '_blank', 'noopener,noreferrer');
}

$('search').addEventListener('input', (ev) => { searchTerm = ev.target.value.trim(); renderEntries(); });
$('search').addEventListener('keydown', (ev) => { if (ev.key === 'Escape') { ev.target.value = ''; searchTerm = ''; renderEntries(); } });

// ---------- Eintrag-Dialog ----------

let editingId = null;
const updateEntryMeter = bindMeter($('e-password'), $('e-meter'), $('e-meter-text'));

// space: 'both' (Einträge), 'shared' oder 'personal' (Ordner bleiben in ihrem Bereich)
function fillFolderSelect(select, selected, { allowRoot = false, exclude = null, rootLabel = '(kein Ordner)', space = 'both' } = {}) {
  const opts = [];
  const walk = (parent, depth) => {
    for (const f of childrenOf(parent)) {
      if (exclude && exclude.has(f.id)) continue;
      opts.push(el('option', { value: f.id }, '\u00a0\u00a0'.repeat(depth) + f.name));
      walk(f.id, depth + 1);
    }
  };
  if (space !== 'personal') {
    if (allowRoot) opts.push(el('option', { value: '' }, rootLabel));
    walk('', 0);
  }
  if (space !== 'shared' && data.personal && data.personal.available) {
    opts.push(el('option', { value: PERSONAL }, '🔒 Persönlicher Tresor'));
    walk(PERSONAL, 1);
  }
  select.replaceChildren(...opts);
  select.value = selected || '';
}

async function openEntry(id) {
  editingId = id;
  $('entry-error').textContent = '';
  $('e-password').type = 'password';
  let e = { title: '', username: '', password: '', url: '', notes: '', tags: [], folderId: currentFolder || (data.folders[0] && data.folders[0].id) || '' };
  if (id) {
    try { e = await api('GET', 'entries/' + id); } catch (err) { toast(err.message, true); return; }
    if (e.personal && !e.folderId) e.folderId = PERSONAL;
  }
  $('entry-dlg-title').textContent = id ? 'Eintrag bearbeiten' : 'Neuer Eintrag';
  fillFolderSelect($('e-folder'), e.folderId, { allowRoot: true });
  $('e-title').value = e.title;
  $('e-username').value = e.username;
  $('e-password').value = e.password;
  $('e-url').value = e.url;
  $('e-notes').value = e.notes;
  $('e-tags').value = (e.tags || []).join(', ');
  $('e-delete').classList.toggle('hidden', !id);
  const hist = e.history || [];
  $('e-history-wrap').classList.toggle('hidden', hist.length === 0);
  $('e-history').replaceChildren(...hist.map((h) => el('li', {},
    el('span', { class: 'muted' }, new Date(h.changedAt).toLocaleString('de-DE')),
    el('code', {}, '••••••••'),
    el('button', { type: 'button', class: 'icon', title: 'Anzeigen', onclick: (ev) => { const c = ev.target.parentElement.querySelector('code'); c.textContent = c.textContent === h.password ? '••••••••' : h.password; } }, '👁'),
    el('button', { type: 'button', class: 'icon', title: 'Kopieren', onclick: () => copyText(h.password, 'Altes Passwort') }, '⧉'),
  )));
  $('e-meta').textContent = id ? `Angelegt: ${new Date(e.created).toLocaleString('de-DE')} · Geändert: ${new Date(e.updated).toLocaleString('de-DE')}${e.updatedBy ? ' von ' + e.updatedBy : ''}` : '';
  updateEntryMeter();
  $('dlg-entry').showModal();
  $('e-title').focus();
}

$('btn-new-entry').addEventListener('click', () => openEntry(null));
$('e-toggle').addEventListener('click', () => { const p = $('e-password'); p.type = p.type === 'password' ? 'text' : 'password'; });
$('e-open-url').addEventListener('click', () => { if ($('e-url').value) openUrl($('e-url').value); });
$('e-generate').addEventListener('click', () => openGenerator((pw) => { $('e-password').value = pw; $('e-password').type = 'text'; updateEntryMeter(); }));

$('entry-form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const folder = $('e-folder').value;
  const body = {
    id: editingId || '',
    title: $('e-title').value,
    folderId: serverFolder(folder),
    personal: isPersonal(folder),
    username: $('e-username').value,
    password: $('e-password').value,
    url: $('e-url').value.trim(),
    notes: $('e-notes').value,
    tags: $('e-tags').value.split(',').map((t) => t.trim()).filter(Boolean),
  };
  try {
    await api('POST', 'entries', body);
    $('dlg-entry').close();
    toast('Gespeichert');
    await reload();
  } catch (e) { $('entry-error').textContent = e.message; }
});

$('e-delete').addEventListener('click', async () => {
  if (!editingId || !confirm(`Eintrag „${$('e-title').value}“ wirklich löschen?`)) return;
  try {
    await api('DELETE', 'entries/' + editingId);
    $('dlg-entry').close();
    toast('Gelöscht');
    await reload();
  } catch (e) { $('entry-error').textContent = e.message; }
});

// ---------- Ordner ----------

let editingFolder = null;

function openFolder(f) {
  editingFolder = f;
  $('folder-error').textContent = '';
  $('folder-dlg-title').textContent = f ? 'Ordner bearbeiten' : 'Neuer Ordner';
  $('f-name').value = f ? f.name : '';
  // Bestehende Ordner bleiben in ihrem Bereich, neue können in beiden angelegt werden.
  const space = f ? (f.personal ? 'personal' : 'shared') : 'both';
  fillFolderSelect($('f-parent'), f ? f.parentId : currentFolder, { allowRoot: true, exclude: f ? descendants(f.id) : null, rootLabel: '(oberste Ebene)', space });
  $('dlg-folder').showModal();
  $('f-name').focus();
}

$('btn-new-folder').addEventListener('click', () => openFolder(null));
$('btn-edit-folder').addEventListener('click', () => openFolder(data.folders.find((f) => f.id === currentFolder)));
$('btn-delete-folder').addEventListener('click', async () => {
  const f = data.folders.find((x) => x.id === currentFolder);
  if (!f) return;
  const n = data.entries.filter((e) => descendants(f.id).has(e.folderId)).length;
  if (!confirm(`Ordner „${f.name}“ mit allen Unterordnern und ${n} Einträgen löschen?`)) return;
  try {
    await api('DELETE', 'folders/' + f.id);
    currentFolder = '';
    toast('Ordner gelöscht');
    await reload();
  } catch (e) { toast(e.message, true); }
});

$('folder-form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  try {
    const parent = $('f-parent').value;
    const f = await api('POST', 'folders', { id: editingFolder ? editingFolder.id : '', name: $('f-name').value, parentId: serverFolder(parent), personal: isPersonal(parent) });
    $('dlg-folder').close();
    currentFolder = f.id;
    await reload();
  } catch (e) { $('folder-error').textContent = e.message; }
});

// ---------- Persönlicher Tresor nach AD-Passwortwechsel ----------

function openPersonalUnlock() {
  $('p-old').value = '';
  $('personal-error').textContent = '';
  $('dlg-personal').showModal();
  $('p-old').focus();
}

$('personal-form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  try {
    await api('POST', 'personal/unlock', { oldPassword: $('p-old').value });
    $('p-old').value = '';
    $('dlg-personal').close();
    toast('Persönlicher Tresor entsperrt');
    currentFolder = PERSONAL;
    await reload();
  } catch (e) { $('personal-error').textContent = e.message; }
});

$('p-reset').addEventListener('click', async () => {
  if (!confirm('Persönlichen Tresor leeren? Die bisherigen persönlichen Einträge sind dann endgültig verloren.')) return;
  try {
    await api('POST', 'personal/reset');
    $('dlg-personal').close();
    toast('Persönlicher Tresor neu angelegt');
    await reload();
  } catch (e) { $('personal-error').textContent = e.message; }
});

// ---------- Generator ----------

let generatorCallback = null;

function genOptions() {
  const mode = document.querySelector('input[name=gen-mode]:checked').value;
  if (mode === 'words') {
    return { mode, words: Number($('gen-wordcount').value), separator: $('gen-sep').value, upper: $('gen-w-upper').checked, digits: $('gen-w-digit').checked };
  }
  return {
    mode, length: Number($('gen-length').value),
    lower: $('gen-lower').checked, upper: $('gen-upper').checked, digits: $('gen-digits').checked,
    symbols: $('gen-symbols').checked, excludeAmbiguous: $('gen-ambiguous').checked,
  };
}

async function generate() {
  const o = genOptions();
  $('gen-chars').classList.toggle('hidden', o.mode !== 'chars');
  $('gen-words').classList.toggle('hidden', o.mode !== 'words');
  $('gen-length-val').textContent = $('gen-length').value;
  $('gen-words-val').textContent = $('gen-wordcount').value;
  try {
    const r = await api('POST', 'generate', o);
    $('gen-result').value = r.password;
    $('gen-entropy').textContent = `Entropie: ~${Math.round(r.entropy)} Bit`;
  } catch (e) {
    $('gen-result').value = '';
    $('gen-entropy').textContent = e.message;
  }
}

function openGenerator(cb) {
  generatorCallback = cb || null;
  $('gen-use').classList.toggle('hidden', !cb);
  $('dlg-generator').showModal();
  generate();
}

$('gen-form').addEventListener('input', generate);
$('gen-refresh').addEventListener('click', generate);
$('gen-use').addEventListener('click', () => {
  if (generatorCallback) generatorCallback($('gen-result').value);
  $('dlg-generator').close();
});
$('btn-generator').addEventListener('click', () => openGenerator(null));

// ---------- Einstellungen ----------

function openSettings() {
  setSettingsError('');
  $('s-autolock').value = data.settings.autoLockMinutes;
  $('s-clipboard').value = data.settings.clipboardSeconds;
  $('s-recovery-left').textContent = data.recoveryRemaining;
  $('s-path').textContent = data.path;
  for (const x of document.querySelectorAll('.kf-current')) x.classList.toggle('hidden', !data.keyFileNeeded);
  $('mfa-reset-form').classList.remove('hidden');
  $('mfa-confirm-form').classList.add('hidden');
  $('m-recovery').classList.add('hidden');
  restoreUserSections();
  prepareAdminSections();
  $('cred-form').classList.toggle('hidden', !!data.ad);
  $('x-pw').placeholder = data.ad ? 'Dein AD-Passwort zur Bestätigung' : 'Dein Passwort zur Bestätigung';
  $('s-conn').textContent = connLabel(data.connection);
  $('dlg-settings').showModal();
}

const roleLabel = { admin: 'Admin', user: 'Benutzer' };

// Fehler der Benutzer-/AD-Abschnitte; die stehen in den Einstellungen oder im Einrichtungsassistenten.
function setSettingsError(msg) {
  $('settings-error').textContent = msg;
  $('wz-error5').textContent = msg;
}

function prepareAdminSections() {
  setSettingsError('');
  $('u-start').classList.add('hidden');
  for (const x of document.querySelectorAll('.admin-only')) x.classList.toggle('hidden', data.role !== 'admin');
  loadUsers();
  if (data.role === 'admin') loadAD();
}

function showStartPassword(name, pw) {
  $('u-start-name').textContent = name;
  $('u-start-pw').value = pw;
  $('u-start').classList.remove('hidden');
}

async function userAction(fn) {
  setSettingsError('');
  try {
    await fn();
    await loadUsers();
  } catch (e) { setSettingsError(e.message); }
}

async function loadUsers() {
  let r;
  try { r = await api('GET', 'users'); } catch (e) { setSettingsError(e.message); return; }
  const rows = r.users.map((u) => {
    const me = u.name.toLowerCase() === r.me.toLowerCase();
    const state = (u.ad ? 'AD-Konto · ' : '') + (u.mustChange ? 'Wartet auf erste Anmeldung' : (u.mfa ? 'MFA eingerichtet' : 'MFA wird beim Anmelden eingerichtet'));
    const enc = encodeURIComponent(u.name);
    const actions = [];
    if (r.admin && !me && u.ad) {
      actions.push(
        el('button', { type: 'button', class: 'icon', title: 'MFA zurücksetzen (Handy verloren). Beim nächsten Anmelden richtet der Benutzer sie neu ein.', onclick: () => {
          if (!confirm(`Authenticator von ${u.name} zurücksetzen?`)) return;
          userAction(async () => { await api('POST', `users/${enc}/reset`); toast(`MFA von ${u.name} zurückgesetzt`); });
        } }, '↺'),
        el('button', { type: 'button', class: 'icon', title: 'Aus der Liste entfernen. Den Zugang selbst steuert die AD-Gruppe.', onclick: () => {
          if (!confirm(`${u.name} aus der Liste entfernen? Solange ${u.name} in der AD-Gruppe ist, ist eine erneute Anmeldung möglich (mit neuer MFA). Den Zugang nimmst du über die AD-Gruppe weg. Der persönliche Tresor von ${u.name} wird gelöscht.`)) return;
          userAction(() => api('DELETE', `users/${enc}`));
        } }, '🗑'),
      );
    } else if (r.admin && !me) {
      const other = u.role === 'admin' ? 'user' : 'admin';
      actions.push(
        el('button', { type: 'button', class: 'icon', title: `Zu ${roleLabel[other]} machen`, onclick: () => userAction(() => api('PUT', `users/${enc}/role`, { role: other })) }, u.role === 'admin' ? '⬇' : '⬆'),
        el('button', { type: 'button', class: 'icon', title: 'Neues Startpasswort und MFA zurücksetzen (Passwort vergessen, Handy verloren)', onclick: () => {
          if (!confirm(`${u.name} ein neues Startpasswort geben? Das bisherige Passwort und die Authenticator-App von ${u.name} gelten dann nicht mehr, und der persönliche Tresor von ${u.name} wird geleert (er ist an das alte Passwort gebunden).`)) return;
          userAction(async () => showStartPassword(u.name, (await api('POST', `users/${enc}/reset`)).startPassword));
        } }, '↺'),
        el('button', { type: 'button', class: 'icon', title: 'Benutzer entfernen', onclick: () => {
          if (!confirm(`${u.name} aus dem Tresor entfernen? ${u.name} kann den Tresor danach nicht mehr öffnen, der persönliche Tresor von ${u.name} wird gelöscht.`)) return;
          userAction(() => api('DELETE', `users/${enc}`));
        } }, '🗑'),
      );
    }
    return el('tr', {},
      el('td', {}, u.name, me ? el('span', { class: 'me' }, ' (du)') : null),
      el('td', {}, roleLabel[u.role] || u.role),
      el('td', {}, state, u.keyFile ? ' · Schlüsseldatei' : ''),
      el('td', { class: 'actions' }, actions));
  });
  $('user-rows').replaceChildren(...rows);
}

// ---------- Active Directory ----------

function adFormConfig() {
  return {
    server: $('ad-server').value.trim(), domain: $('ad-domain').value.trim(), group: $('ad-group').value.trim(),
    role: $('ad-role').value, baseDN: $('ad-basedn').value.trim(), skipVerify: $('ad-skipverify').checked,
  };
}

async function loadAD() {
  $('ad-status').textContent = '';
  try {
    const r = await api('GET', 'ad');
    const c = r.config;
    $('ad-keyfile').textContent = r.keyFile;
    $('ad-server').value = c ? c.server : '';
    $('ad-domain').value = c ? c.domain : '';
    $('ad-group').value = c ? c.group : '';
    $('ad-role').value = c ? c.role || 'user' : 'user';
    $('ad-basedn').value = c ? c.baseDN || '' : '';
    $('ad-skipverify').checked = !!(c && c.skipVerify);
    $('ad-save').textContent = c ? 'Speichern' : 'AD-Anmeldung einschalten';
    $('ad-disable').classList.toggle('hidden', !c);
    for (const x of $('ad-form').querySelectorAll('input, select, button')) x.disabled = !r.local;
    if (!r.local) $('ad-status').textContent = 'Die AD-Einstellungen kann nur ein lokaler Admin ändern.';
    else if (c) $('ad-status').textContent = `Eingeschaltet für Gruppe ${c.group}.`;
  } catch (e) { setSettingsError(e.message); }
}

$('ad-test').addEventListener('click', async () => {
  const btn = $('ad-test');
  busy(btn, true);
  $('ad-status').textContent = 'Prüfe …';
  try {
    const r = await api('POST', 'ad/test', { config: adFormConfig(), user: $('ad-test-user').value, password: $('ad-test-pw').value });
    $('ad-status').textContent = `✓ Verbindung ok: ${r.user} ist in der Gruppe.`;
  } catch (e) {
    $('ad-status').textContent = '✗ ' + e.message;
  } finally {
    $('ad-test-pw').value = '';
    busy(btn, false);
  }
});

$('ad-form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  try {
    const r = await api('PUT', 'ad', adFormConfig());
    toast('AD-Anmeldung gespeichert. Jetzt die Rechte der .adkey-Datei auf die Gruppe beschränken!', false, 8000);
    await loadAD();
    $('ad-keyfile').textContent = r.keyFile;
  } catch (e) { $('ad-status').textContent = '✗ ' + e.message; }
});

$('ad-disable').addEventListener('click', async () => {
  if (!confirm('AD-Anmeldung ausschalten? AD-Benutzer kommen dann nicht mehr hinein, der Tresor wird neu verschlüsselt.')) return;
  try {
    await api('DELETE', 'ad');
    toast('AD-Anmeldung ausgeschaltet');
    await loadAD();
    await loadUsers();
  } catch (e) { $('ad-status').textContent = '✗ ' + e.message; }
});

$('user-add-form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const name = $('u-name').value.trim();
  await userAction(async () => {
    const r = await api('POST', 'users', { name, role: $('u-role').value });
    $('u-name').value = '';
    showStartPassword(name, r.startPassword);
  });
});

$('btn-settings').addEventListener('click', openSettings);

$('settings-form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  try {
    await api('PUT', 'settings', { autoLockMinutes: Number($('s-autolock').value), clipboardSeconds: Number($('s-clipboard').value) });
    toast('Einstellungen gespeichert');
    await reload();
  } catch (e) { setSettingsError(e.message); }
});

$('cred-form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  setSettingsError('');
  if ($('c-new').value !== $('c-new2').value) { setSettingsError('Die neuen Passwörter stimmen nicht überein.'); return; }
  const btn = ev.submitter;
  busy(btn, true);
  try {
    await api('POST', 'credentials', {
      currentPassword: $('c-current').value,
      currentKeyFile: await readFileB64($('c-current-kf')),
      newPassword: $('c-new').value,
      newKeyFile: await readFileB64($('c-new-kf')),
    });
    ev.target.reset();
    toast('Zugangsdaten geändert');
    await reload();
    openSettings();
  } catch (e) { setSettingsError(e.message); } finally { busy(btn, false); }
});

$('mfa-reset-form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  try {
    const t = await api('POST', 'mfa/reset', { code: $('m-current').value });
    $('m-current').value = '';
    $('m-qr').src = t.qr;
    $('m-secret').textContent = t.secret.replace(/(.{4})/g, '$1 ').trim();
    $('mfa-reset-form').classList.add('hidden');
    $('mfa-confirm-form').classList.remove('hidden');
  } catch (e) { setSettingsError(e.message); }
});

$('mfa-confirm-form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  try {
    const r = await api('POST', 'mfa/confirm', { code: $('m-code').value });
    $('m-code').value = '';
    $('mfa-confirm-form').classList.add('hidden');
    $('m-recovery').replaceChildren(...r.recoveryCodes.map((c) => el('li', {}, c)));
    $('m-recovery').classList.remove('hidden');
    toast('Authenticator neu eingerichtet. Neue Wiederherstellungscodes sicher aufbewahren!', false, 6000);
    data.recoveryRemaining = r.recoveryCodes.length;
    $('s-recovery-left').textContent = data.recoveryRemaining;
  } catch (e) { setSettingsError(e.message); }
});

$('i-file').addEventListener('change', async (ev) => {
  try {
    const csv = await readFileText(ev.target);
    if (!csv) return;
    const r = await api('POST', 'import', { csv, folderId: serverFolder(currentFolder), personal: isPersonal(currentFolder) });
    const names = { title: 'Titel', username: 'Benutzer', password: 'Passwort', url: 'URL', notes: 'Notizen', desc: 'Beschreibung', folder: 'Ordner', tags: 'Tags' };
    const cols = r.columns || {};
    const mapped = Object.keys(names).filter((f) => cols[f]).map((f) => `${cols[f]} → ${names[f]}`).join(', ');
    toast(`${r.imported} Einträge importiert. Spalten: ${mapped}`, false, 8000);
    if (r.ignored && r.ignored.length) toast(`Nicht übernommen: ${r.ignored.join(', ')}`, false, 8000);
    ev.target.value = '';
    await reload();
  } catch (e) { setSettingsError(e.message); }
});

$('export-form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  try {
    const res = await api('POST', 'export', { password: $('x-pw').value, keyFile: await readFileB64($('x-kf')) });
    const blob = await res.blob();
    const name = (res.headers.get('Content-Disposition') || '').match(/filename="([^"]+)"/);
    const a = el('a', { href: URL.createObjectURL(blob), download: name ? name[1] : 'passmind-export.csv' });
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
    $('x-pw').value = '';
    toast('Export erstellt. Datei nach Gebrauch sicher löschen!', false, 6000);
  } catch (e) { setSettingsError(e.message); }
});

// ---------- Speicherort ----------

let browseMode = 'pick';   // 'pick' (Einrichtungsassistent: Ort wählen) oder 'move' (geöffneten Tresor verschieben)
let browseDir = '';
let browseSep = '/';

function joinPath(dir, name) {
  return dir.endsWith(browseSep) ? dir + name : dir + browseSep + name;
}

async function browse(path) {
  $('browse-error').textContent = '';
  try {
    const r = await api('GET', 'fs' + (path ? '?path=' + encodeURIComponent(path) : ''));
    browseDir = r.path;
    browseSep = r.sep;
    $('browse-path').value = r.path;
    const shortcuts = [...(r.home ? [['🏠 Benutzerordner', r.home]] : []), ...r.roots.map((x) => ['💽 ' + x, x])];
    $('browse-roots').replaceChildren(...shortcuts.map(([label, p]) =>
      el('button', { type: 'button', class: 'btn secondary', onclick: () => browse(p) }, label)));
    const items = [];
    if (r.parent) items.push(el('li', { onclick: () => browse(r.parent) }, '⬆ ', '.. (übergeordneter Ordner)'));
    for (const d of r.dirs) items.push(el('li', { onclick: () => browse(joinPath(r.path, d)) }, '📁 ', d));
    for (const v of r.vaults) {
      items.push(el('li', { class: 'vault', onclick: () => { $('browse-name').value = v; } }, '🔐 ', v));
    }
    if (!r.dirs.length && !r.vaults.length) items.push(el('li', { class: 'empty' }, 'Keine Unterordner oder Tresore'));
    $('browse-list').replaceChildren(...items);
  } catch (e) {
    $('browse-error').textContent = e.message;
  }
}

function openBrowser(mode, startPath = '') {
  browseMode = mode;
  const pick = mode === 'pick';
  $('browse-name').value = pick ? ($('wz-name').value || 'passmind.vault') : 'passmind.vault';
  $('browse-title').textContent = pick ? (wizard.kind === 'new' ? 'Ordner für den neuen Tresor' : 'Vorhandenen Tresor wählen') : 'Tresor verschieben';
  $('browse-hint').textContent = pick && wizard.kind === 'existing'
    ? 'Die .vault-Datei anklicken. Netzwerkpfade wie \\\\NAS\\Freigabe kannst du oben direkt eintippen.'
    : 'Ordner wählen, z. B. ein Netzlaufwerk auf dem NAS. Netzwerkpfade wie \\\\NAS\\Freigabe kannst du oben direkt eintippen.';
  $('browse-ok').textContent = pick ? 'Übernehmen' : 'Hierhin verschieben';
  const conn = (pick ? status.connection : data.connection) || {};
  $('browse-auth').classList.toggle('hidden', !conn.supported);
  $('browse-auth').open = false;
  $('browse-net-pw').value = '';
  $('dlg-browse').showModal();
  browse(startPath);
}

$('browse-connect').addEventListener('click', async () => {
  $('browse-error').textContent = '';
  try {
    const r = await api('POST', 'connect', { path: $('browse-path').value.trim(), user: $('browse-net-user').value.trim(), password: $('browse-net-pw').value });
    $('browse-net-pw').value = '';
    toast(`Mit ${r.share} verbunden`);
    if (browseMode === 'pick') {
      setMode('network');
      $('wz-net-user').value = $('browse-net-user').value.trim();
      status.connection = { ...status.connection, mode: 'network', user: $('wz-net-user').value };
    }
    browse($('browse-path').value.trim());
  } catch (e) { $('browse-error').textContent = e.message; }
});

function connLabel(c) {
  if (!c) return '';
  if (c.mode === 'network') return `Verbindungsart: Netzwerk-Anmeldung als ${c.user} an ${c.share}`;
  return 'Verbindungsart: Standard (angemeldeter Benutzer)';
}

async function selectVault(path) {
  try {
    const r = await api('POST', 'vault/select', { path });
    $('dlg-browse').close();
    toast(r.exists ? 'Tresor gewählt' : 'Neuer Speicherort gewählt');
    status = await api('GET', 'status');
    if (status.exists) showLocked(); else startSetup();
  } catch (e) {
    $('browse-error').textContent = e.message;
    if (!$('dlg-browse').open) toast(e.message, true);
  }
}

$('browse-go').addEventListener('click', () => browse($('browse-path').value));
$('browse-path').addEventListener('keydown', (ev) => { if (ev.key === 'Enter') { ev.preventDefault(); browse($('browse-path').value); } });
for (const a of document.querySelectorAll('.choose-vault')) {
  a.addEventListener('click', (ev) => { ev.preventDefault(); startSetup(true); });
}
$('s-move').addEventListener('click', () => openBrowser('move'));

$('browse-form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const dir = $('browse-path').value.trim() || browseDir;
  const target = joinPath(dir, $('browse-name').value.trim() || 'passmind.vault');
  if (browseMode === 'pick') {
    $('wz-dir').value = dir;
    $('wz-name').value = $('browse-name').value.trim() || 'passmind.vault';
    $('dlg-browse').close();
    return;
  }
  try {
    const r = await api('POST', 'vault/move', { path: target });
    $('dlg-browse').close();
    toast(`Tresor verschoben. Die alte Datei liegt weiterhin unter ${r.oldPath}.`, false, 8000);
    await reload();
    $('s-path').textContent = data.path;
    $('s-conn').textContent = connLabel(data.connection);
  } catch (e) { $('browse-error').textContent = e.message; }
});

// ---------- Sperren, Beenden, Aktivität ----------

function closeAllDialogs() {
  for (const d of document.querySelectorAll('dialog[open]')) d.close();
}

// Design: dunkel (PassMind-Stil, Standard) oder hell (klassisch)
function updateThemeButton() {
  const light = document.documentElement.dataset.theme === 'light';
  $('btn-theme').textContent = light ? '🌙' : '☀';
  $('btn-theme').title = light ? 'Dunkles Design (PassMind)' : 'Helles Design (klassisch)';
}
// Das Design wird in der passmind.json gespeichert und von theme.js vor dem Zeichnen gesetzt.
function applyTheme(theme) {
  if (theme === 'light') document.documentElement.dataset.theme = 'light'; else delete document.documentElement.dataset.theme;
  updateThemeButton();
  api('PUT', 'theme', { theme }).catch((e) => toast(e.message, true));
}
$('btn-theme').addEventListener('click', () => applyTheme(document.documentElement.dataset.theme === 'light' ? 'dark' : 'light'));

// Frühere Versionen merkten sich das Design im Browser.
function migrateTheme() {
  let old = '';
  try { old = localStorage.getItem('pm-theme') || ''; localStorage.removeItem('pm-theme'); } catch { /* egal */ }
  if (old && !status.theme) applyTheme(old);
}
updateThemeButton();

$('btn-lock').addEventListener('click', async () => {
  await api('POST', 'lock').catch(() => {});
  data = { folders: [], entries: [], settings: {} };
  $('entry-rows').replaceChildren();
  showLocked();
});

$('btn-quit').addEventListener('click', async () => {
  if (!confirm('PassMind beenden? Der Tresor wird gesperrt.')) return;
  await api('POST', 'quit').catch(() => {});
  closeAllDialogs();
  document.body.replaceChildren(el('div', { class: 'auth view' }, el('div', { class: 'card' },
    el('h1', {}, 'PassMind wurde beendet'), el('p', { class: 'muted' }, 'Du kannst dieses Fenster jetzt schließen.'))));
});

// Benutzeraktivität höchstens alle 30 s an den Server melden, damit die Auto-Sperre nicht greift.
let lastPing = 0;
for (const evName of ['keydown', 'mousedown', 'mousemove', 'wheel', 'touchstart']) {
  document.addEventListener(evName, () => {
    if (!data.folders.length && !data.entries.length && $('view-main').classList.contains('hidden')) return;
    const now = Date.now();
    if (now - lastPing > 30000) {
      lastPing = now;
      api('POST', 'ping').catch(() => {});
    }
  }, { passive: true });
}

// Regelmäßig prüfen, ob der Server den Tresor (z. B. wegen Inaktivität) gesperrt hat.
setInterval(async () => {
  if ($('view-main').classList.contains('hidden')) return;
  try {
    const s = await api('GET', 'status');
    if (!s.unlocked) {
      data = { folders: [], entries: [], settings: {} };
      $('entry-rows').replaceChildren();
      toast('Tresor wurde automatisch gesperrt');
      showLocked();
    }
  } catch { /* Server beendet */ }
}, 15000);

document.addEventListener('keydown', (ev) => {
  if ($('view-main').classList.contains('hidden') || document.querySelector('dialog[open]')) return;
  if ((ev.ctrlKey || ev.metaKey) && ev.key === 'f') { ev.preventDefault(); $('search').focus(); }
  if ((ev.ctrlKey || ev.metaKey) && ev.key === 'n') { ev.preventDefault(); openEntry(null); }
  if ((ev.ctrlKey || ev.metaKey) && ev.key === 'l') { ev.preventDefault(); $('btn-lock').click(); }
});

init();
