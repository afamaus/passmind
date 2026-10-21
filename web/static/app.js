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
  if (!status.exists) startSetup();
  else if (!status.unlocked) showLocked();
  else await openMain();
}

// ---------- Einrichtung ----------

let setupState = {};

function setStep(n) {
  for (const li of document.querySelectorAll('.steps li')) {
    const s = Number(li.dataset.step);
    li.classList.toggle('active', s === n);
    li.classList.toggle('done', s < n);
  }
  ['setup-step1', 'setup-step2', 'setup-step3'].forEach((id, i) => $(id).classList.toggle('hidden', i + 1 !== n));
}

function startSetup() {
  show('view-setup');
  $('setup-path').textContent = status.path;
  $('setup-missing').classList.toggle('hidden', !status.missingKnown);
  setStep(1);
  $('setup-pw').focus();
}

bindMeter($('setup-pw'), $('setup-meter'), $('setup-meter-text'));

$('setup-step1').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const pw = $('setup-pw').value, pw2 = $('setup-pw2').value;
  $('setup-error1').textContent = '';
  if (pw.length < 10) { $('setup-error1').textContent = 'Mindestens 10 Zeichen.'; return; }
  if (pw !== pw2) { $('setup-error1').textContent = 'Die Passwörter stimmen nicht überein.'; return; }
  try {
    setupState = { password: pw, keyFile: await readFileB64($('setup-keyfile')) };
    const t = await api('POST', 'setup/totp');
    $('setup-qr').src = t.qr;
    $('setup-secret').textContent = t.secret.replace(/(.{4})/g, '$1 ').trim();
    setStep(2);
    $('setup-code').focus();
  } catch (e) {
    $('setup-error1').textContent = e.message;
  }
});

$('setup-back').addEventListener('click', () => setStep(1));

$('setup-step2').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const btn = ev.submitter;
  busy(btn, true);
  $('setup-error2').textContent = '';
  try {
    const r = await api('POST', 'setup', { ...setupState, code: $('setup-code').value });
    setupState = { codes: r.recoveryCodes };
    $('setup-recovery').replaceChildren(...r.recoveryCodes.map((c) => el('li', {}, c)));
    setStep(3);
  } catch (e) {
    $('setup-error2').textContent = e.message;
  } finally {
    busy(btn, false);
  }
});

$('setup-copy-codes').addEventListener('click', () => {
  navigator.clipboard.writeText(setupState.codes.join('\n')).then(() => toast('Codes kopiert'));
});

$('setup-done').addEventListener('click', () => {
  setupState = {};
  $('setup-pw').value = $('setup-pw2').value = $('setup-code').value = '';
  openMain();
});

// ---------- Entsperren ----------

let useRecovery = false;

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
  $('unlock-keyfile-wrap').classList.toggle('hidden', !status.keyFileNeeded);
  $('unlock-pw').value = '';
  $('unlock-code').value = '';
  $('unlock-recovery').value = '';
  $('unlock-pw').focus();
  if (status.error) $('unlock-error').textContent = status.error;
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
    const body = { password: $('unlock-pw').value, keyFile: await readFileB64($('unlock-keyfile')) };
    if (useRecovery) body.recoveryCode = $('unlock-recovery').value; else body.code = $('unlock-code').value;
    const r = await api('POST', 'unlock', body);
    $('unlock-pw').value = '';
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

// ---------- Hauptansicht ----------

let data = { folders: [], entries: [], settings: {} };
let currentFolder = '';   // '' = alle Einträge
let searchTerm = '';

async function openMain() {
  await reload();
  show('view-main');
  $('search').focus();
}

async function reload() {
  data = await api('GET', 'data');
  clipboardSeconds = data.settings.clipboardSeconds || 20;
  if (currentFolder && !data.folders.some((f) => f.id === currentFolder)) currentFolder = '';
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
  return parts.join(' / ');
}

function folderNode(f) {
  const count = data.entries.filter((e) => descendants(f.id).has(e.folderId)).length;
  const node = el('div', {
    class: 'node' + (currentFolder === f.id ? ' active' : ''),
    onclick: () => { currentFolder = f.id; renderTree(); renderEntries(); },
  }, '📁 ', f.name, el('span', { class: 'count' }, count));
  // Einträge per Drag & Drop in Ordner verschieben
  node.addEventListener('dragover', (ev) => { ev.preventDefault(); node.classList.add('drop'); });
  node.addEventListener('dragleave', () => node.classList.remove('drop'));
  node.addEventListener('drop', async (ev) => {
    ev.preventDefault();
    node.classList.remove('drop');
    const id = ev.dataTransfer.getData('text/entry-id');
    if (!id) return;
    try {
      const full = await api('GET', 'entries/' + id);
      full.folderId = f.id;
      await api('POST', 'entries', full);
      toast(`Verschoben nach „${f.name}“`);
      await reload();
    } catch (e) { toast(e.message, true); }
  });
  const kids = childrenOf(f.id);
  return el('li', {}, node, kids.length ? el('ul', {}, kids.map(folderNode)) : null);
}

function renderTree() {
  const all = el('div', {
    class: 'node' + (currentFolder === '' ? ' active' : ''),
    onclick: () => { currentFolder = ''; renderTree(); renderEntries(); },
  }, '🗂 Alle Einträge', el('span', { class: 'count' }, data.entries.length));
  $('folder-tree').replaceChildren(el('li', {}, all), ...childrenOf('').map(folderNode));
  $('list-title').textContent = currentFolder ? folderPath(currentFolder) : 'Alle Einträge';
  $('btn-edit-folder').classList.toggle('hidden', !currentFolder);
  $('btn-delete-folder').classList.toggle('hidden', !currentFolder);
}

function matches(e, term) {
  if (!term) return true;
  const hay = [e.title, e.username, e.url, e.notes, ...(e.tags || [])].join('\n').toLowerCase();
  return term.toLowerCase().split(/\s+/).every((t) => hay.includes(t));
}

function renderEntries() {
  const scope = currentFolder ? descendants(currentFolder) : null;
  const list = data.entries
    .filter((e) => (searchTerm ? true : !scope || scope.has(e.folderId)))
    .filter((e) => matches(e, searchTerm))
    .sort((a, b) => a.title.localeCompare(b.title, 'de'));
  const rows = list.map((e) => {
    const tr = el('tr', { draggable: 'true', onclick: () => openEntry(e.id) },
      el('td', { class: 'title' }, e.title,
        (searchTerm || !currentFolder) && e.folderId ? el('span', { class: 'folder-hint' }, folderPath(e.folderId)) : null),
      el('td', {}, e.username),
      passwordCell(e.id),
      el('td', { class: 'url hide-sm' }, e.url),
      el('td', { class: 'hide-sm' }, (e.tags || []).map((t) => el('span', { class: 'tag' }, t))),
      el('td', { class: 'actions' },
        el('button', { class: 'icon', title: 'Benutzer kopieren', onclick: (ev) => { ev.stopPropagation(); copyText(e.username, 'Benutzername'); } }, '👤'),
        el('button', { class: 'icon', title: 'Passwort kopieren', onclick: (ev) => { ev.stopPropagation(); copyPassword(e.id); } }, '🔑'),
        e.url ? el('button', { class: 'icon', title: 'URL öffnen', onclick: (ev) => { ev.stopPropagation(); openUrl(e.url); } }, '↗') : null,
      ));
    tr.addEventListener('dragstart', (ev) => ev.dataTransfer.setData('text/entry-id', e.id));
    return tr;
  });
  $('entry-rows').replaceChildren(...rows);
  $('empty-hint').classList.toggle('hidden', rows.length > 0);
  $('empty-hint').textContent = searchTerm ? 'Keine Treffer.' : 'Keine Einträge. Lege mit „Neuer Eintrag“ den ersten an.';
}

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

function fillFolderSelect(select, selected, { allowRoot = false, exclude = null, rootLabel = '(kein Ordner)' } = {}) {
  const opts = [];
  if (allowRoot) opts.push(el('option', { value: '' }, rootLabel));
  const walk = (parent, depth) => {
    for (const f of childrenOf(parent)) {
      if (exclude && exclude.has(f.id)) continue;
      opts.push(el('option', { value: f.id }, '  '.repeat(depth) + f.name));
      walk(f.id, depth + 1);
    }
  };
  walk('', 0);
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
  $('e-meta').textContent = id ? `Angelegt: ${new Date(e.created).toLocaleString('de-DE')} · Geändert: ${new Date(e.updated).toLocaleString('de-DE')}` : '';
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
  const body = {
    id: editingId || '',
    title: $('e-title').value,
    folderId: $('e-folder').value,
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
  fillFolderSelect($('f-parent'), f ? f.parentId : currentFolder, { allowRoot: true, exclude: f ? descendants(f.id) : null, rootLabel: '(oberste Ebene)' });
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
    const f = await api('POST', 'folders', { id: editingFolder ? editingFolder.id : '', name: $('f-name').value, parentId: $('f-parent').value });
    $('dlg-folder').close();
    currentFolder = f.id;
    await reload();
  } catch (e) { $('folder-error').textContent = e.message; }
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
  $('settings-error').textContent = '';
  $('s-autolock').value = data.settings.autoLockMinutes;
  $('s-clipboard').value = data.settings.clipboardSeconds;
  $('s-recovery-left').textContent = data.recoveryRemaining;
  $('s-path').textContent = data.path;
  for (const x of document.querySelectorAll('.kf-current')) x.classList.toggle('hidden', !data.keyFileNeeded);
  $('mfa-reset-form').classList.remove('hidden');
  $('mfa-confirm-form').classList.add('hidden');
  $('m-recovery').classList.add('hidden');
  $('dlg-settings').showModal();
}

$('btn-settings').addEventListener('click', openSettings);

$('settings-form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  try {
    await api('PUT', 'settings', { autoLockMinutes: Number($('s-autolock').value), clipboardSeconds: Number($('s-clipboard').value) });
    toast('Einstellungen gespeichert');
    await reload();
  } catch (e) { $('settings-error').textContent = e.message; }
});

$('cred-form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  $('settings-error').textContent = '';
  if ($('c-new').value !== $('c-new2').value) { $('settings-error').textContent = 'Die neuen Passwörter stimmen nicht überein.'; return; }
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
  } catch (e) { $('settings-error').textContent = e.message; } finally { busy(btn, false); }
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
  } catch (e) { $('settings-error').textContent = e.message; }
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
  } catch (e) { $('settings-error').textContent = e.message; }
});

$('i-file').addEventListener('change', async (ev) => {
  try {
    const csv = await readFileText(ev.target);
    if (!csv) return;
    const r = await api('POST', 'import', { csv, folderId: currentFolder });
    toast(`${r.imported} Einträge importiert`);
    ev.target.value = '';
    await reload();
  } catch (e) { $('settings-error').textContent = e.message; }
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
  } catch (e) { $('settings-error').textContent = e.message; }
});

// ---------- Speicherort ----------

let browseMode = 'select';   // 'select' (gesperrt: Tresor wählen/anlegen) oder 'move' (geöffneten Tresor verschieben)
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

function openBrowser(mode) {
  browseMode = mode;
  const current = mode === 'move' ? data.path : status.path;
  const name = (current || '').split(/[\\/]/).pop() || 'passmind.vault';
  $('browse-name').value = mode === 'move' ? 'passmind.vault' : name;
  $('browse-title').textContent = mode === 'move' ? 'Tresor verschieben' : 'Tresor wählen oder neu anlegen';
  $('browse-hint').textContent = mode === 'move'
    ? 'Ordner wählen, z. B. ein Netzlaufwerk auf dem NAS. Netzwerkpfade wie \\\\NAS\\Freigabe kannst du oben direkt eintippen.'
    : 'Vorhandene .vault-Datei anklicken oder Ordner und Dateinamen für einen neuen Tresor wählen.';
  $('browse-ok').textContent = mode === 'move' ? 'Hierhin verschieben' : 'Diesen Tresor verwenden';
  $('dlg-browse').showModal();
  browse('');
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
  a.addEventListener('click', (ev) => { ev.preventDefault(); openBrowser('select'); });
}
$('s-move').addEventListener('click', () => openBrowser('move'));

$('browse-form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const dir = $('browse-path').value.trim() || browseDir;
  const target = joinPath(dir, $('browse-name').value.trim() || 'passmind.vault');
  if (browseMode === 'select') { selectVault(target); return; }
  try {
    const r = await api('POST', 'vault/move', { path: target });
    $('dlg-browse').close();
    toast(`Tresor verschoben. Die alte Datei liegt weiterhin unter ${r.oldPath}.`, false, 8000);
    await reload();
    $('s-path').textContent = data.path;
  } catch (e) { $('browse-error').textContent = e.message; }
});

// ---------- Sperren, Beenden, Aktivität ----------

function closeAllDialogs() {
  for (const d of document.querySelectorAll('dialog[open]')) d.close();
}

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
