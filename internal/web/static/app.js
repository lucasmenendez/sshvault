'use strict';

/* ------------------------------------------------------------------ */
/* Utilities                                                           */
/* ------------------------------------------------------------------ */

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

class ApiError extends Error {
  constructor(code, message, status, detail) {
    super(message);
    this.name = 'ApiError';
    this.code = code;
    this.status = status;
    this.detail = detail || {};
  }
}

function h(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props || {})) {
    if (key === 'hidden') { node.hidden = Boolean(value); continue; }
    if (value === undefined || value === null || value === false) continue;
    if (key === 'class') node.className = value;
    else if (key === 'text') node.textContent = value;
    else if (key === 'dataset') Object.assign(node.dataset, value);
    else if (key === 'style') Object.assign(node.style, value);
    else if (key === 'value' || key === 'checked' || key === 'disabled' || key === 'selected' || key === 'indeterminate') node[key] = value;
    else if (key.startsWith('on') && typeof value === 'function') node.addEventListener(key.slice(2).toLowerCase(), value);
    else node.setAttribute(key, value === true ? '' : String(value));
  }
  append(node, children);
  return node;
}

function append(node, children) {
  for (const child of children.flat(Infinity)) {
    if (child === undefined || child === null || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
}

function icon(name, cls = '') {
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('class', `icon ${cls}`.trim());
  svg.setAttribute('aria-hidden', 'true');
  const use = document.createElementNS('http://www.w3.org/2000/svg', 'use');
  use.setAttribute('href', `#i-${name}`);
  svg.append(use);
  return svg;
}

function mapButtonClass(className = '') {
  const parts = String(className).split(/\s+/).filter(Boolean);
  const has = (name) => parts.includes(name);
  if (has('row-action')) {
    return ['row-action', has('danger') ? 'danger' : '', has('warn') ? 'warn' : ''].filter(Boolean).join(' ');
  }
  const out = [];
  if (has('primary')) {
    // Sumi's default button is the primary button.
  } else if (has('ghost')) {
    out.push('ghost');
  } else if (has('danger')) {
    out.push('danger');
  } else {
    out.push('secondary');
  }
  if (has('sm')) out.push('small');
  if (has('icon-only')) out.push('icon-only');
  if (has('wide')) out.push('wide');
  return out.join(' ');
}

function btn(label, iconName, onClick, className = 'btn', title = '') {
  const b = h('button', {
    type: 'button',
    class: mapButtonClass(className),
    title: title || undefined,
    onclick: onClick || undefined,
  });
  if (iconName) b.append(icon(iconName));
  if (label) b.append(h('span', { text: label }));
  return b;
}

function iconBtn(name, title, onClick, extra = '') {
  return btn('', name, onClick, `ghost icon-only ${extra}`.trim(), title);
}

function field(label, control, hint) {
  return h('label', { class: 'field' },
    h('span', { text: label }),
    control,
    hint ? h('span', { class: 'hint', text: hint }) : null,
  );
}

function parseTags(value) {
  const out = [];
  const seen = new Set();
  for (const part of String(value || '').split(',')) {
    const t = part.trim();
    if (!t) continue;
    const k = t.toLowerCase();
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(t);
  }
  return out;
}

function tagsText(tags) {
  return (tags || []).join(', ');
}

function fmtDate(value) {
  if (!value) return '—';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return '—';
  return new Intl.DateTimeFormat('en-US', { dateStyle: 'medium', timeStyle: 'short' }).format(d);
}

function fmtSize(bytes) {
  if (!Number.isFinite(bytes)) return '—';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function modeString(mode) {
  if (!mode) return '—';
  return '0' + (mode & 0o777).toString(8);
}

function shortFp(fp) {
  if (!fp) return 'no fingerprint';
  if (fp.length <= 28) return fp;
  return `${fp.slice(0, 14)}…${fp.slice(-8)}`;
}

function fmtDuration(seconds) {
  if (!seconds) return 'Disabled';
  if (seconds < 60) return `${seconds} s`;
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes} min`;
  const hours = Math.round(minutes / 60);
  return `${hours} h`;
}

function plural(n, one, many) {
  return `${n} ${n === 1 ? one : many}`;
}

function downloadBlobUrl(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = h('a', { href: url, download: filename });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

function toBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

function fromBase64(b64) {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function decodeText(buffer) {
  try {
    const text = new TextDecoder('utf-8', { fatal: true }).decode(buffer);
    if (text.includes('\u0000')) return null;
    return text;
  } catch {
    return null;
  }
}

/* ------------------------------------------------------------------ */
/* State + API                                                         */
/* ------------------------------------------------------------------ */

const state = {
  data: null,
  view: 'keys',
  search: { keys: '', hosts: '', files: '' },
  tags: new Set(),
  tagMode: 'all',
  identityFilter: new Set(),
  selection: new Set(),
  theme: localStorage.getItem('sshvault-theme') || '',
  busy: false,
  needsSetup: false,
  canPickVault: false,
};

let reloadedForSession = false;
let activePopover = null;

async function api(path, { method = 'GET', body } = {}) {
  if (body === undefined && method !== 'GET') body = {};
  const opts = { method, credentials: 'same-origin', headers: {} };
  if (body !== undefined) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(path, opts);
  const ct = res.headers.get('content-type') || '';
  let payload = null;
  if (ct.includes('application/json')) {
    try { payload = await res.json(); } catch { payload = null; }
  } else {
    try { payload = await res.text(); } catch { payload = null; }
  }
  if (res.status === 423) {
    showLock();
    throw new ApiError('locked', 'The vault is locked', 423, payload?.error);
  }
  if (res.status === 401 && !reloadedForSession) {
    const code = payload?.error?.code;
    if (code === 'no_session') {
      reloadedForSession = true;
      location.reload();
    }
    throw new ApiError(code || 'no_session', payload?.error?.message || 'Invalid session', 401, payload?.error);
  }
  if (!res.ok) {
    const err = payload?.error || {};
    throw new ApiError(err.code || 'http_error', err.message || `HTTP error ${res.status}`, res.status, err);
  }
  return payload;
}

async function load(showBoot = false) {
  if (showBoot) {
    $('#boot').hidden = false;
    $('#shell').hidden = true;
  }
  const data = await api('/api/bootstrap');
  state.data = data;
  const ids = new Set([...data.keys, ...data.hosts, ...data.files].map((x) => x.id));
  state.selection = new Set([...state.selection].filter((id) => ids.has(id)));
  hideLock();
  $('#boot').hidden = true;
  $('#shell').hidden = false;
  renderShell();
  render();
}

function toastError(err) {
  if (!err) return;
  if (err.code === 'locked') {
    showLock();
    return;
  }
  if (err.code === 'no_session') return;
  if (err.code === 'revision') {
    toast('The vault changed in another tab; reloading…', 'err');
    load().catch(() => {});
    return;
  }
  toast(err.message || String(err), 'err');
}

/* ------------------------------------------------------------------ */
/* Toasts                                                              */
/* ------------------------------------------------------------------ */

function toast(message, kind = 'info', timeout = 4600) {
  const box = h('div', { class: `toast ${kind}` },
    icon(kind === 'ok' ? 'check' : kind === 'err' ? 'alert' : 'shield'),
    h('span', { class: 'prewrap', text: message }),
    h('button', { class: 'close', type: 'button', title: 'Close', onclick: () => box.remove() }, icon('x', 'sm')),
  );
  $('#toasts').append(box);
  if (timeout > 0) setTimeout(() => box.remove(), timeout);
}

/* ------------------------------------------------------------------ */
/* Rendering: shell, header, banners                                   */
/* ------------------------------------------------------------------ */

function renderShell() {
  if (!state.data) return;
  $('#count-keys').textContent = state.data.keys.length;
  $('#count-hosts').textContent = state.data.hosts.length;
  $('#count-files').textContent = state.data.files.length;
  const base = state.data.vault.path.split('/').pop() || 'ssh.vault';
  $('#brand-sub').textContent = base;
  $('#side-ssh').textContent = state.data.sshDir;
  $('#side-version').textContent = state.data.version === 'dev' ? 'dev' : `v${state.data.version}`;
  $$('.nav-item[data-view]').forEach((item) => {
    item.classList.toggle('active', item.dataset.view === state.view);
  });
}

function render() {
  if (!state.data) return;
  const viewRoot = $('#view');
  if (viewRoot) viewRoot.dataset.view = state.view;
  closeAllPopovers();
  renderHeader();
  renderBanner();
  switch (state.view) {
    case 'keys': renderKeys(); break;
    case 'hosts': renderHosts(); break;
    case 'files': renderFiles(); break;
    case 'settings': renderSettings(); break;
    default: setView('keys');
  }
}

function renderHeader() {
  const meta = {
    keys: ['Keys', 'Keys and certificates stored inside the vault.'],
    hosts: ['Hosts', 'Entries from ~/.ssh/config and the keys they use.'],
    files: ['Files', 'Other files in ~/.ssh, such as known_hosts or authorized_keys.'],
    settings: ['Settings', 'Vault status and security options.'],
  }[state.view] || ['sshvault', ''];

  let actions = [];
  if (state.view === 'keys') {
    actions = [
      btn('Import', 'upload', openImport, 'btn'),
      btn('New key', 'plus', () => openKeyEditor(null), 'btn primary'),
    ];
  } else if (state.view === 'hosts') {
    actions = [
      btn('View config', 'file', openConfigPreview, 'btn'),
      btn('New host', 'plus', () => openHostEditor(null), 'btn primary'),
    ];
  } else if (state.view === 'files') {
    actions = [
      btn('Scan ~/.ssh', 'refresh', openImport, 'btn'),
      btn('New file', 'plus', () => openFileEditor(null), 'btn primary'),
    ];
  }

  const header = $('#main-header');
  const titleNode = h('div', { class: 'header-title' },
    h('h1', { text: meta[0] }),
    h('p', { text: meta[1] }),
  );
  const actionsNode = actions.length ? h('div', { class: 'header-actions' }, ...actions) : null;
  header.replaceChildren(...[titleNode, actionsNode].filter(Boolean));
}

function renderBanner() {
  const box = $('#banner');
  box.replaceChildren();
  if (state.data.configError) {
    box.append(h('div', { class: 'banner danger' },
      icon('alert'),
      h('span', { class: 'prewrap', text: `Cannot manage ~/.ssh/config: ${state.data.configError}` }),
    ));
    return;
  }
  if (state.data.configWarnings?.length) {
    const list = state.data.configWarnings;
    box.append(h('div', { class: 'banner warn' },
      icon('alert'),
      h('span', { class: 'truncate', text: list[0] + (list.length > 1 ? ` (+${list.length - 1} more)` : '') }),
      btn('View', null, () => openWarnings('Configuration warnings', list,
        'These hosts are defined in both the managed block and outside it. The block is at the top of ~/.ssh/config, so its values take precedence; review duplicate entries if you want to avoid confusion.',
        [btn('Resolve duplicates', 'alert', () => { closeModalSafe(); openDuplicates(); }, 'btn primary')]), 'btn sm'),
    ));
  }
}

function setView(view, updateHash = true) {
  if (!['keys', 'hosts', 'files', 'settings'].includes(view)) return;
  state.view = view;
  state.selection.clear();
  if (updateHash && location.hash !== `#${view}`) history.replaceState(null, '', `#${view}`);
  renderShell();
  render();
}

/* ------------------------------------------------------------------ */
/* Shared controls                                                     */
/* ------------------------------------------------------------------ */

function attachPopover(anchor, build, align = 'left', options = {}) {
  if (options.portal) {
    anchor.addEventListener('click', (ev) => {
      ev.stopPropagation();
      if (activePopover?.anchor === anchor) { closeAllPopovers(); return; }
      closeAllPopovers();
      openPortalPopover(anchor, build, align);
    });
    return anchor;
  }
  const wrap = h('div', { class: 'popover-wrap' }, anchor);
  anchor.addEventListener('click', (ev) => {
    ev.stopPropagation();
    if (activePopover) closeAllPopovers();
    const open = wrap.querySelector('.popover');
    if (open) { open.remove(); return; }
    closeAllPopovers();
    const panel = h('div', { class: `popover ${align === 'right' ? 'right' : ''}`.trim() });
    panel.addEventListener('click', (ev2) => ev2.stopPropagation());
    build(panel);
    wrap.append(panel);
  });
  return wrap;
}

function openPortalPopover(anchor, build, align) {
  const panel = h('div', { class: 'popover portal' });
  panel.addEventListener('click', (ev) => ev.stopPropagation());
  build(panel);
  panel.style.visibility = 'hidden';
  document.body.append(panel);

  const place = () => {
    if (!panel.isConnected) return;
    const pad = 8;
    const gap = 7;
    const rect = anchor.getBoundingClientRect();
    const width = panel.offsetWidth;
    const height = panel.offsetHeight;
    let left = align === 'right' ? rect.right - width : rect.left;
    left = Math.min(Math.max(pad, left), Math.max(pad, window.innerWidth - width - pad));
    let top = rect.bottom + gap;
    if (top + height > window.innerHeight - pad) {
      const above = rect.top - height - gap;
      top = above >= pad ? above : Math.max(pad, window.innerHeight - height - pad);
    }
    panel.style.left = `${Math.round(left)}px`;
    panel.style.top = `${Math.round(top)}px`;
    panel.style.visibility = 'visible';
  };
  place();

  const onScroll = () => {
    const rect = anchor.getBoundingClientRect();
    if (rect.bottom < 0 || rect.top > window.innerHeight || rect.right < 0 || rect.left > window.innerWidth) {
      closeAllPopovers();
      return;
    }
    place();
  };
  window.addEventListener('scroll', onScroll, true);
  window.addEventListener('resize', onScroll);
  activePopover = {
    anchor,
    panel,
    cleanup: () => {
      window.removeEventListener('scroll', onScroll, true);
      window.removeEventListener('resize', onScroll);
    },
  };
}

function closeAllPopovers() {
  $$('.popover').forEach((p) => p.remove());
  if (activePopover) {
    if (activePopover.cleanup) activePopover.cleanup();
    activePopover = null;
  }
}

function closePortalPopover() {
  if (activePopover) closeAllPopovers();
  closeAllRowDropdowns();
}

function closeAllRowDropdowns(except = null) {
  $$('details.row-dropdown[open]').forEach((d) => {
    if (d !== except) d.open = false;
  });
}

function dropdownItem(label, iconName, fn, close) {
  return h('li', {},
    h('a', {
      href: '#',
      onclick: (ev) => {
        ev.preventDefault();
        ev.stopPropagation();
        close();
        fn();
      },
    }, iconName ? icon(iconName, 'sm') : null, h('span', { text: label })),
  );
}

function rowDropdown(label, iconName, build) {
  const details = h('details', { class: 'dropdown row-dropdown' });
  const summary = h('summary', { class: 'row-action' }, icon(iconName), h('span', { text: label }));
  const menu = h('ul', { class: 'row-menu' });
  const close = () => { if (details.open) details.open = false; };
  build(menu, close);
  details.append(summary, menu);

  let cleanup = null;
  const place = () => {
    if (!details.open) return;
    const rect = summary.getBoundingClientRect();
    const width = menu.offsetWidth;
    const height = menu.offsetHeight;
    const pad = 8;
    const gap = 6;
    let left = Math.min(Math.max(pad, rect.right - width), Math.max(pad, window.innerWidth - width - pad));
    let top = rect.bottom + gap;
    if (top + height > window.innerHeight - pad) {
      const above = rect.top - height - gap;
      top = above >= pad ? above : Math.max(pad, window.innerHeight - height - pad);
    }
    menu.style.left = `${Math.round(left)}px`;
    menu.style.top = `${Math.round(top)}px`;
    menu.style.visibility = 'visible';
  };
  const onDocClick = (ev) => { if (!details.contains(ev.target)) close(); };
  const onKey = (ev) => { if (ev.key === 'Escape') { close(); summary.focus(); } };
  const onScroll = () => close();
  const onResize = () => close();

  details.addEventListener('toggle', () => {
    if (details.open) {
      closeAllPopovers();
      closeAllRowDropdowns(details);
      document.body.append(menu);
      menu.style.visibility = 'hidden';
      place();
      requestAnimationFrame(place);
      document.addEventListener('click', onDocClick);
      document.addEventListener('keydown', onKey);
      window.addEventListener('scroll', onScroll, true);
      window.addEventListener('resize', onResize);
      cleanup = () => {
        document.removeEventListener('click', onDocClick);
        document.removeEventListener('keydown', onKey);
        window.removeEventListener('scroll', onScroll, true);
        window.removeEventListener('resize', onResize);
      };
    } else {
      if (cleanup) cleanup();
      cleanup = null;
      details.append(menu);
      menu.style.visibility = 'hidden';
    }
  });

  return details;
}

function menuItem(label, iconName, fn, danger = false) {
  return h('button', {
    type: 'button',
    class: `popover-item${danger ? ' danger-text' : ''}`,
    onclick: () => { closeAllPopovers(); fn(); },
  }, iconName ? icon(iconName, 'sm') : null, h('span', { text: label }));
}

function searchControl(placeholder, value, oninput) {
  return h('div', { class: 'search-wrap' },
    icon('search'),
    h('input', {
      class: 'input',
      type: 'search',
      placeholder,
      value,
      'aria-label': placeholder,
      oninput: (e) => oninput(e.target.value),
      onkeydown: (e) => { if (e.key === 'Escape') { e.target.value = ''; oninput(''); } },
    }),
  );
}

function allTagsWithCounts() {
  const counts = new Map();
  const add = (tags) => {
    for (const t of tags || []) {
      const key = t.toLowerCase();
      const cur = counts.get(key);
      counts.set(key, { label: cur?.label || t, n: (cur?.n || 0) + 1 });
    }
  };
  state.data.keys.forEach((k) => add(k.tags));
  state.data.files.forEach((f) => add(f.tags));
  return [...counts.entries()].sort((a, b) => a[1].label.localeCompare(b[1].label));
}

function tagFilterControl() {
  const active = state.tags.size;
  const button = btn(active ? `Tags (${active})` : 'Tags', 'filter', null, 'btn');
  if (active) button.append(h('span', { class: 'dot' }));
  return attachPopover(button, (panel) => {
    panel.append(h('h4', { text: 'Filter by tag' }));
    const tags = allTagsWithCounts();
    if (!tags.length) {
      panel.append(h('div', { class: 'popover-empty', text: 'No tags yet.' }));
      return;
    }
    const list = h('div', { class: 'popover-list' });
    for (const [key, info] of tags) {
      const cb = h('input', {
        type: 'checkbox',
        class: 'checkbox',
        checked: state.tags.has(key),
        onchange: (e) => {
          if (e.target.checked) state.tags.add(key);
          else state.tags.delete(key);
          refreshLists();
        },
      });
      list.append(h('label', { class: 'popover-item' }, cb, h('span', { text: info.label }), h('span', { class: 'count', text: info.n })));
    }
    panel.append(list);
    panel.append(h('div', { class: 'popover-footer' },
      h('label', { class: 'switch' },
        h('input', {
          type: 'checkbox',
          checked: state.tagMode === 'all',
          onchange: (e) => { state.tagMode = e.target.checked ? 'all' : 'any'; refreshLists(); },
        }),
        'All',
      ),
      h('div', { class: 'spacer' }),
      btn('Clear', null, () => {
        state.tags.clear();
        refreshLists();
        closeAllPopovers();
      }, 'btn sm ghost'),
    ));
  });
}

function identityFilterControl() {
  const active = state.identityFilter.size;
  const button = btn(active ? `IdentityFile (${active})` : 'IdentityFile', 'filter', null, 'btn');
  if (active) button.append(h('span', { class: 'dot' }));
  return attachPopover(button, (panel) => {
    panel.append(h('h4', { text: 'Filter by key' }));
    if (!state.data.keys.length) {
      panel.append(h('div', { class: 'popover-empty', text: 'No keys in the vault.' }));
      return;
    }
    const list = h('div', { class: 'popover-list' });
    for (const key of state.data.keys) {
      const cb = h('input', {
        type: 'checkbox',
        class: 'checkbox',
        checked: state.identityFilter.has(key.id),
        onchange: (e) => {
          if (e.target.checked) state.identityFilter.add(key.id);
          else state.identityFilter.delete(key.id);
          renderHostList();
        },
      });
      list.append(h('label', { class: 'popover-item' }, cb, h('span', { text: key.alias }), h('span', { class: 'count mono', text: key.filename })));
    }
    panel.append(list);
    panel.append(h('div', { class: 'popover-footer' },
      btn('Clear', null, () => {
        state.identityFilter.clear();
        renderHostList();
        closeAllPopovers();
      }, 'btn sm ghost'),
    ));
  });
}

function refreshLists() {
  if (state.view === 'keys') renderKeyList();
  else if (state.view === 'files') renderFileList();
  else if (state.view === 'hosts') renderHostList();
}

function statusBadge(status) {
  const map = {
    deployed: ['Local', 'ok'],
    not_deployed: ['Not deployed', 'muted'],
    partial: ['Partial', 'warn'],
    drift: ['Modified', 'danger'],
    mode: ['Permissions', 'warn'],
    blocked: ['Conflict', 'danger'],
  };
  const [label, cls] = map[status?.state] || [status?.state || '—', 'muted'];
  return h('span', { class: `badge ${cls}`, title: status?.message || label }, h('span', { class: 'dot' }), label);
}

function tagChips(tags, limit = 4) {
  if (!tags?.length) return h('span', { class: 'muted', text: '—' });
  const shown = tags.slice(0, limit);
  return h('div', { class: 'tags' },
    ...shown.map((t) => h('span', { class: 'tag', text: t })),
    tags.length > limit ? h('span', { class: 'tag', text: `+${tags.length - limit}` }) : null,
  );
}

function emptyState(iconName, title, text, actions = []) {
  return h('div', { class: 'empty' },
    h('div', { class: 'empty-mark' }, icon(iconName, 'lg')),
    h('h3', { text: title }),
    h('p', { text }),
    actions.length ? h('div', { class: 'inline wrap' }, ...actions) : null,
  );
}

function bulkBar(kind) {
  const count = selectedOf(kind).length;
  if (!count) return null;
  return h('div', { class: 'bulk-bar' },
    h('strong', { text: `${count} selected` }),
    btn('Deploy', 'save', () => bulkDeploy(kind), 'btn sm'),
    btn('Remove local', 'eject', () => bulkUndeploy(kind), 'btn sm'),
    btn('Delete', 'trash', () => bulkDelete(kind), 'btn sm danger'),
    h('div', { class: 'spacer' }),
    btn('Clear', null, () => { state.selection.clear(); refreshLists(); }, 'btn sm ghost'),
  );
}

function selectedOf(kind) {
  return (state.data?.[kind] || []).filter((x) => state.selection.has(x.id));
}

function selectAllControl(visibleIds) {
  const selected = visibleIds.filter((id) => state.selection.has(id)).length;
  const cb = h('input', {
    type: 'checkbox',
    class: 'checkbox',
    checked: visibleIds.length > 0 && selected === visibleIds.length,
    indeterminate: selected > 0 && selected < visibleIds.length,
    'aria-label': 'Select all',
    onchange: (e) => {
      if (e.target.checked) visibleIds.forEach((id) => state.selection.add(id));
      else visibleIds.forEach((id) => state.selection.delete(id));
      refreshLists();
    },
  });
  return cb;
}

/* ------------------------------------------------------------------ */
/* Keys                                                                */
/* ------------------------------------------------------------------ */

function filteredKeys() {
  const q = state.search.keys.trim().toLowerCase();
  const tags = [...state.tags];
  return state.data.keys
    .filter((k) => {
      if (q) {
        const hay = [k.alias, k.filename, k.comment, k.fingerprint, ...(k.tags || [])].join(' ').toLowerCase();
        if (!hay.includes(q)) return false;
      }
      if (tags.length) {
        const lower = (k.tags || []).map((t) => t.toLowerCase());
        const ok = state.tagMode === 'all' ? tags.every((t) => lower.includes(t)) : tags.some((t) => lower.includes(t));
        if (!ok) return false;
      }
      return true;
    })
    .sort((a, b) => a.alias.localeCompare(b.alias));
}

function renderKeys() {
  const root = $('#view');
  root.replaceChildren();
  const toolbar = h('div', { class: 'toolbar' },
    searchControl('Search by alias, tag, or fingerprint…', state.search.keys, (v) => { state.search.keys = v; renderKeyList(); }),
    tagFilterControl(),
    h('div', { class: 'toolbar-meta', id: 'keys-meta' }),
  );
  root.append(toolbar, h('div', { id: 'keys-list' }));
  renderKeyList();
}

function renderKeyList() {
  closePortalPopover();
  const box = $('#keys-list');
  if (!box) return;
  const keys = filteredKeys();
  const meta = $('#keys-meta');
  if (meta) meta.textContent = `${keys.length} of ${state.data.keys.length}`;
  box.replaceChildren();

  const bulk = bulkBar('keys');
  if (bulk) box.append(bulk);

  if (!state.data.keys.length) {
    box.append(emptyState('key', 'No keys yet', 'Create a new key or import the ones you already have in ~/.ssh.', [
      btn('New key', 'plus', () => openKeyEditor(null), 'btn primary'),
      btn('Import', 'upload', openImport, 'btn'),
    ]));
    return;
  }
  if (!keys.length) {
    box.append(emptyState('search', 'No results', 'Try another alias or clear the filters.', [
      btn('Clear filters', null, () => { state.search.keys = ''; state.tags.clear(); renderKeys(); }, 'btn'),
    ]));
    return;
  }

  const table = h('table', { class: 'data-table keys-table' },
    h('colgroup', {},
      h('col', { class: 'col-check' }),
      h('col', { class: 'col-main' }),
      h('col', { class: 'col-tags' }),
      h('col', { class: 'col-status' }),
      h('col', { class: 'col-actions' }),
    ),
    h('thead', {}, h('tr', {},
      h('th', { class: 'col-check' }, selectAllControl(keys.map((k) => k.id))),
      h('th', { text: 'Alias' }),
      h('th', { text: 'Tags' }),
      h('th', { text: 'Status' }),
      h('th', { class: 'actions-col' }),
    )),
    h('tbody', {}, ...keys.map((k) => renderKeyRow(k))),
  );
  box.append(h('div', { class: 'table-wrap overflow-auto' }, table));
}

function rowActivation(label, open) {
  return {
    tabindex: '0',
    'aria-label': label,
    onclick: (e) => {
      if (e.target.closest('button, input, a, label, summary')) return;
      open();
    },
    onkeydown: (e) => {
      if (e.target.closest('button, input, a, label, summary')) return;
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        open();
      }
    },
  };
}

function renderKeyRow(key) {
  const selected = state.selection.has(key.id);
  const info = key.info || {};
  const typeLabel = key.kind === 'certificate' ? 'cert' : (info.type || key.kind).replace(/^ssh-/, '');
  const name = h('div', { class: 'cell' },
    h('div', { class: 'name-row' },
      h('div', { class: 'avatar' }, icon(key.kind === 'certificate' ? 'shield' : 'key')),
      h('div', { class: 'cell-stack' },
        h('div', { class: 'name-row' },
          h('strong', { class: 'name', text: key.alias }),
          h('span', { class: 'type', text: typeLabel }),
          info.cert?.expired ? h('span', { class: 'badge danger', text: 'expired' }) : null,
        ),
        h('span', { class: 'fingerprint', title: key.fingerprint || '', text: shortFp(key.fingerprint) }),
      ),
    ),
  );

  const actions = [copyKeyMenu(key)];
  const kstate = key.status.state;
  if (kstate === 'drift' || kstate === 'blocked') {
    actions.push(btn('Resolve', 'alert', () => resolveKeyConflict(key), 'row-action warn'));
  } else if (kstate === 'not_deployed' || kstate === 'partial' || kstate === 'mode') {
    actions.push(btn('Deploy', 'save', () => deployKey(key), 'row-action'));
  } else {
    actions.push(btn('Remove local', 'eject', () => undeployKey(key), 'row-action danger'));
  }

  return h('tr', { class: `data-row${selected ? ' selected' : ''}`, ...rowActivation(`Open key ${key.alias}`, () => openKeyEditor(key)) },
    h('td', { class: 'col-check' },
      h('input', {
        type: 'checkbox',
        class: 'checkbox',
        checked: selected,
        'aria-label': `Select ${key.alias}`,
        onchange: (e) => {
          if (e.target.checked) state.selection.add(key.id);
          else state.selection.delete(key.id);
          renderKeyList();
        },
      }),
    ),
    h('td', {}, name),
    h('td', {}, tagChips(key.tags)),
    h('td', {}, statusBadge(key.status)),
    h('td', { class: 'actions-col' }, h('div', { class: 'cell-actions' }, ...actions)),
  );
}

function copyKeyMenu(key) {
  return rowDropdown('Copy', 'copy', (menu, close) => {
    if (key.hasPublic) menu.append(dropdownItem('Public key', 'key', () => copyText(key.publicKey, 'Public key copied'), close));
    if (key.hasPrivate) menu.append(dropdownItem('Private key', 'lock', () => copyPrivateKey(key), close));
    if (key.hasCert) menu.append(dropdownItem('Certificate', 'shield', () => copyKeySecret(key, 'certificate', 'Certificate copied'), close));
    menu.append(dropdownItem('Fingerprint', 'tag', () => copyText(key.fingerprint, 'Fingerprint copied'), close));
  });
}

async function copyKeySecret(key, field, label) {
  try {
    const res = await api(`/api/keys/${key.id}/secret/${field}`);
    await copyText(res.value, label);
  } catch (e) { toastError(e); }
}

async function copyPrivateKey(key) {
  const r = await confirmAction({
    title: 'Copy private key',
    message: `The private key for “${key.alias}” will be copied to the clipboard. Any process with clipboard access could read it.`,
    confirmText: 'Copy key',
    danger: true,
  });
  if (!r.ok) return;
  await copyKeySecret(key, 'private', 'Private key copied');
}

async function copyText(text, label = 'Copied') {
  if (!text) { toast('Nothing to copy', 'err'); return; }
  try {
    await navigator.clipboard.writeText(text);
    toast(label, 'ok');
  } catch {
    const ta = h('textarea', { style: { position: 'fixed', opacity: '0', left: '-9999px' } });
    ta.value = text;
    document.body.append(ta);
    ta.select();
    try { document.execCommand('copy'); toast(label, 'ok'); }
    catch { toast('Could not copy to the clipboard', 'err'); }
    ta.remove();
  }
}

async function deployKey(key) {
  try {
    await api(`/api/keys/${key.id}/deploy`, { method: 'POST', body: { force: false } });
    toast(`“${key.alias}” deployed to ${state.data.sshDir}`, 'ok');
    await load();
  } catch (e) {
    if (e.status === 409) await resolveKeyConflict(key);
    else toastError(e);
  }
}

async function resolveKeyConflict(key) {
  const r = await confirmAction({
    title: 'Local conflict',
    message: `The local files for “${key.alias}” do not match the vault. You can overwrite them with the vault version or adopt the local changes into the vault.`,
    confirmText: 'Overwrite local',
    danger: true,
    extra: { label: 'Adopt local changes' },
  });
  if (r.extra) {
    try {
      await api(`/api/keys/${key.id}/adopt-local`, { method: 'POST', body: {} });
      toast('Local changes adopted into the vault', 'ok');
      await load();
    } catch (e) { toastError(e); }
  } else if (r.ok) {
    try {
      await api(`/api/keys/${key.id}/deploy`, { method: 'POST', body: { force: true } });
      toast('Local files overwritten', 'ok');
      await load();
    } catch (e) { toastError(e); }
  }
}

async function undeployKey(key) {
  const r = await confirmAction({
    title: 'Remove local',
    message: `The local files for “${key.alias}” will be deleted. The definition will remain in the vault.`,
    confirmText: 'Remove local',
    danger: true,
  });
  if (!r.ok) return;
  try {
    await api(`/api/keys/${key.id}/undeploy`, { method: 'POST', body: { force: true } });
    toast('Local files deleted', 'ok');
    await load();
  } catch (e) { toastError(e); }
}

async function deleteKey(key) {
  const r = await confirmAction({
    title: 'Delete key from vault',
    message: `“${key.alias}” will be deleted from the encrypted vault. This cannot be undone except from backups.`,
    confirmText: 'Delete',
    danger: true,
    checkLabel: 'Also delete local files',
    checkDefault: false,
  });
  if (!r.ok) return false;
  const local = r.checked ? '1' : '0';
  try {
    await api(`/api/keys/${key.id}?local=${local}&force=0`, { method: 'DELETE' });
    toast('Key deleted', 'ok');
    await load();
    return true;
  } catch (e) {
    if (e.code === 'key_in_use') {
      const hosts = e.detail.hosts || [];
      const r2 = await confirmAction({
        title: 'Key in use',
        message: `“${key.alias}” is used by: ${hosts.join(', ')}. Remove the key from those hosts and delete it from the vault?`,
        confirmText: 'Remove and delete',
        danger: true,
      });
      if (!r2.ok) return false;
      try {
        await api(`/api/keys/${key.id}?local=${local}&force=1`, { method: 'DELETE' });
        toast('Key deleted and removed from hosts', 'ok');
        await load();
        return true;
      } catch (e2) { toastError(e2); return false; }
    } else {
      toastError(e);
      return false;
    }
  }
}

/* ------------------------------------------------------------------ */
/* Hosts                                                               */
/* ------------------------------------------------------------------ */

function filteredHosts() {
  const q = state.search.hosts.trim().toLowerCase();
  return state.data.hosts
    .filter((host) => {
      if (q) {
        const hay = [host.hostname, host.user, ...(host.patterns || [])].join(' ').toLowerCase();
        if (!hay.includes(q)) return false;
      }
      if (state.identityFilter.size) {
        if (!(host.identityKeyIds || []).some((id) => state.identityFilter.has(id))) return false;
      }
      return true;
    })
    .sort((a, b) => (a.patterns[0] || '').localeCompare(b.patterns[0] || ''));
}

function renderHosts() {
  const root = $('#view');
  root.replaceChildren();
  root.append(h('div', { class: 'toolbar' },
    searchControl('Search by host, hostname, or user…', state.search.hosts, (v) => { state.search.hosts = v; renderHostList(); }),
    identityFilterControl(),
    h('div', { class: 'toolbar-meta', id: 'hosts-meta' }),
  ), h('div', { id: 'hosts-list' }));
  renderHostList();
}

function renderHostList() {
  closePortalPopover();
  const box = $('#hosts-list');
  if (!box) return;
  const hosts = filteredHosts();
  const meta = $('#hosts-meta');
  if (meta) meta.textContent = `${hosts.length} of ${state.data.hosts.length}`;
  box.replaceChildren();
  const bulk = bulkBar('hosts');
  if (bulk) box.append(bulk);

  if (!state.data.hosts.length) {
    box.append(emptyState('server', 'No hosts yet', 'Create an entry or import the ones already in ~/.ssh/config.', [
      btn('New host', 'plus', () => openHostEditor(null), 'btn primary'),
    ]));
    return;
  }
  if (!hosts.length) {
    box.append(emptyState('search', 'No results', 'Try another host or clear the IdentityFile filter.', [
      btn('Clear filters', null, () => { state.search.hosts = ''; state.identityFilter.clear(); renderHosts(); }, 'btn'),
    ]));
    return;
  }

  const keysById = new Map(state.data.keys.map((k) => [k.id, k]));
  const table = h('table', { class: 'data-table hosts-table' },
    h('colgroup', {},
      h('col', { class: 'col-check' }),
      h('col', { class: 'col-host' }),
      h('col', { class: 'col-hostname' }),
      h('col', { class: 'col-user' }),
      h('col', { class: 'col-status' }),
      h('col', { class: 'col-actions' }),
    ),
    h('thead', {}, h('tr', {},
      h('th', { class: 'col-check' }, selectAllControl(hosts.map((x) => x.id))),
      h('th', { text: 'Host' }),
      h('th', { text: 'Hostname' }),
      h('th', { text: 'User' }),
      h('th', { text: 'Status' }),
      h('th', { class: 'actions-col' }),
    )),
    h('tbody', {}, ...hosts.map((h) => renderHostRow(h, keysById))),
  );
  box.append(h('div', { class: 'table-wrap overflow-auto' }, table));
}

function renderHostRow(host, keysById) {
  const selected = state.selection.has(host.id);
  const keys = (host.identityKeyIds || []).map((id) => keysById.get(id)).filter(Boolean);
  const port = host.port && host.port !== 22 ? `:${host.port}` : '';
  const actions = [copyHostMenu(host)];
  if (host.status.state === 'drift' || host.status.state === 'blocked') {
    actions.push(btn('Resolve', 'alert', () => resolveHostConflict(host), 'row-action warn'));
  } else if (host.status.state === 'not_deployed') {
    actions.push(btn('Deploy', 'save', () => deployHost(host), 'row-action'));
  } else {
    actions.push(btn('Remove local', 'eject', () => undeployHost(host), 'row-action danger'));
  }
  return h('tr', { class: `data-row${selected ? ' selected' : ''}`, ...rowActivation(`Open host ${host.patterns.join(' ')}`, () => openHostEditor(host)) },
    h('td', { class: 'col-check' },
      h('input', {
        type: 'checkbox',
        class: 'checkbox',
        checked: selected,
        'aria-label': `Select ${host.patterns.join(' ')}`,
        onchange: (e) => {
          if (e.target.checked) state.selection.add(host.id);
          else state.selection.delete(host.id);
          renderHostList();
        },
      }),
    ),
    h('td', {},
      h('div', { class: 'name-row' },
        h('div', { class: 'avatar' }, icon('server')),
        h('div', { class: 'cell-stack' },
          h('strong', { text: host.patterns.join(' ') }),
          h('span', { class: 'sub', text: host.sshCommand || '' }),
        ),
      ),
    ),
    h('td', {},
      h('div', { class: 'cell-stack' },
        h('span', { text: host.hostname || '—' }),
        keys.length
          ? h('div', { class: 'identity-chips' }, ...keys.slice(0, 2).map((k) => h('span', { class: 'identity-chip', text: k.alias })), keys.length > 2 ? h('span', { class: 'identity-chip', text: `+${keys.length - 2}` }) : null)
          : (host.hostname ? null : h('span', { class: 'sub', text: 'no HostName' })),
      ),
    ),
    h('td', {},
      h('div', { class: 'cell-stack' },
        h('span', { text: host.user || '—' }),
        h('span', { class: 'sub mono', text: port || ':22' }),
      ),
    ),
    h('td', {}, statusBadge(host.status)),
    h('td', { class: 'actions-col' }, h('div', { class: 'cell-actions' }, ...actions)),
  );
}

function copyHostMenu(host) {
  return rowDropdown('Command', 'terminal', (menu, close) => {
    menu.append(dropdownItem('ssh ' + (host.patterns[0] || ''), 'terminal', () => copyText(host.sshCommand, 'Command copied'), close));
    menu.append(dropdownItem('Full command', 'terminal', () => copyText(host.sshCommandFull, 'Full command copied'), close));
  });
}

async function deployHost(host) {
  try {
    await api(`/api/hosts/${host.id}/deploy`, { method: 'POST', body: {} });
    toast('Host deployed to ~/.ssh/config', 'ok');
    await load();
  } catch (e) { toastError(e); }
}

async function resolveHostConflict(host) {
  const r = await confirmAction({
    title: 'Config conflict',
    message: `The managed block for “${host.patterns.join(' ')}” changed outside the app. Overwrite it with the vault version?`,
    confirmText: 'Overwrite local',
    danger: true,
  });
  if (!r.ok) return;
  await deployHost(host);
}

async function undeployHost(host) {
  const r = await confirmAction({
    title: 'Remove local host',
    message: `“${host.patterns.join(' ')}” will be removed from the managed block in ~/.ssh/config. The definition will remain in the vault.`,
    confirmText: 'Remove local',
    danger: true,
  });
  if (!r.ok) return;
  try {
    await api(`/api/hosts/${host.id}/undeploy`, { method: 'POST', body: {} });
    toast('Host removed from local config', 'ok');
    await load();
  } catch (e) { toastError(e); }
}

async function deleteHost(host) {
  const r = await confirmAction({
    title: 'Delete host from vault',
    message: `“${host.patterns.join(' ')}” will be deleted from the vault and from the managed block in ~/.ssh/config.`,
    confirmText: 'Delete',
    danger: true,
  });
  if (!r.ok) return false;
  try {
    await api(`/api/hosts/${host.id}`, { method: 'DELETE' });
    toast('Host deleted', 'ok');
    await load();
    return true;
  } catch (e) { toastError(e); return false; }
}

/* ------------------------------------------------------------------ */
/* Files                                                               */
/* ------------------------------------------------------------------ */

function filteredFiles() {
  const q = state.search.files.trim().toLowerCase();
  const tags = [...state.tags];
  return state.data.files
    .filter((f) => {
      if (q) {
        const hay = [f.filename, f.description, ...(f.tags || [])].join(' ').toLowerCase();
        if (!hay.includes(q)) return false;
      }
      if (tags.length) {
        const lower = (f.tags || []).map((t) => t.toLowerCase());
        const ok = state.tagMode === 'all' ? tags.every((t) => lower.includes(t)) : tags.some((t) => lower.includes(t));
        if (!ok) return false;
      }
      return true;
    })
    .sort((a, b) => a.filename.localeCompare(b.filename));
}

function renderFiles() {
  const root = $('#view');
  root.replaceChildren();
  const banner = internalFilesBanner();
  if (banner) root.append(banner);
  root.append(h('div', { class: 'toolbar' },
    searchControl('Search by name or tag…', state.search.files, (v) => { state.search.files = v; renderFileList(); }),
    tagFilterControl(),
    h('div', { class: 'toolbar-meta', id: 'files-meta' }),
  ), h('div', { id: 'files-list' }));
  renderFileList();
}

function internalFilesBanner() {
  const names = state.data.internalFiles || [];
  if (!names.length) return null;
  return h('div', { class: 'banner warn' },
    icon('alert'),
    h('span', { class: 'prewrap', text: `${plural(names.length, 'hidden internal entry', 'hidden internal entries')}: ${names.join(', ')}` }),
    btn('Remove from vault', 'trash', cleanupInternalFiles, 'btn sm'),
  );
}

async function cleanupInternalFiles() {
  const names = state.data.internalFiles || [];
  const r = await confirmAction({
    title: 'Remove internal entries from vault',
    message: `${plural(names.length, 'entry', 'entries')} that point to the vault file or its sidecars will be removed from the vault (${names.join(', ')}). The actual files are not touched.`,
    confirmText: 'Remove from vault',
    danger: true,
  });
  if (!r.ok) return;
  try {
    const res = await api('/api/files/cleanup-internal', {
      method: 'POST',
      body: { revision: state.data.vault.revision },
    });
    toast(`${res.removed?.length || 0} internal entries removed from the vault`, 'ok');
    await load();
  } catch (e) { toastError(e); }
}

function renderFileList() {
  closePortalPopover();
  const box = $('#files-list');
  if (!box) return;
  const files = filteredFiles();
  const meta = $('#files-meta');
  if (meta) meta.textContent = `${files.length} of ${state.data.files.length}`;
  box.replaceChildren();
  const bulk = bulkBar('files');
  if (bulk) box.append(bulk);

  if (!state.data.files.length) {
    box.append(emptyState('file', 'No managed files yet', 'Import known_hosts, authorized_keys, or other files from ~/.ssh, or create a new one.', [
      btn('Scan ~/.ssh', 'refresh', openImport, 'btn primary'),
      btn('New file', 'plus', () => openFileEditor(null), 'btn'),
    ]));
    return;
  }
  if (!files.length) {
    box.append(emptyState('search', 'No results', 'Try another name or clear the filters.', [
      btn('Clear filters', null, () => { state.search.files = ''; state.tags.clear(); renderFiles(); }, 'btn'),
    ]));
    return;
  }

  const table = h('table', { class: 'data-table files-table' },
    h('colgroup', {},
      h('col', { class: 'col-check' }),
      h('col', { class: 'col-main' }),
      h('col', { class: 'col-size' }),
      h('col', { class: 'col-tags' }),
      h('col', { class: 'col-status' }),
      h('col', { class: 'col-actions' }),
    ),
    h('thead', {}, h('tr', {},
      h('th', { class: 'col-check' }, selectAllControl(files.map((f) => f.id))),
      h('th', { text: 'File' }),
      h('th', { text: 'Size' }),
      h('th', { text: 'Tags' }),
      h('th', { text: 'Status' }),
      h('th', { class: 'actions-col' }),
    )),
    h('tbody', {}, ...files.map((f) => renderFileRow(f))),
  );
  box.append(h('div', { class: 'table-wrap overflow-auto' }, table));
}

function renderFileRow(file) {
  const selected = state.selection.has(file.id);
  const actions = [
    btn('Download', 'download', () => downloadFile(file), 'row-action'),
  ];
  if (file.status.state === 'drift' || file.status.state === 'blocked') {
    actions.push(btn('Resolve', 'alert', () => resolveFileConflict(file), 'row-action warn'));
  } else if (file.status.state === 'not_deployed' || file.status.state === 'mode') {
    actions.push(btn('Deploy', 'save', () => deployFile(file), 'row-action'));
  } else {
    actions.push(btn('Remove local', 'eject', () => undeployFile(file), 'row-action danger'));
  }
  return h('tr', { class: `data-row${selected ? ' selected' : ''}`, ...rowActivation(`Open file ${file.filename}`, () => openFileEditor(file)) },
    h('td', { class: 'col-check' },
      h('input', {
        type: 'checkbox',
        class: 'checkbox',
        checked: selected,
        'aria-label': `Select ${file.filename}`,
        onchange: (e) => {
          if (e.target.checked) state.selection.add(file.id);
          else state.selection.delete(file.id);
          renderFileList();
        },
      }),
    ),
    h('td', {},
      h('div', { class: 'name-row' },
        h('div', { class: 'avatar' }, icon('file')),
        h('div', { class: 'cell-stack' },
          h('strong', { class: 'name mono', text: file.filename }),
          h('div', { class: 'inline wrap' },
            file.sensitive ? h('span', { class: 'badge warn', text: 'sensitive' }) : null,
            file.encoding === 'base64' ? h('span', { class: 'badge muted', text: 'binary' }) : null,
            h('span', { class: 'sub', text: file.description || 'no description' }),
          ),
        ),
      ),
    ),
    h('td', {},
      h('div', { class: 'cell-stack' },
        h('span', { text: fmtSize(file.size) }),
        h('span', { class: 'sub mono', text: modeString(file.mode) }),
      ),
    ),
    h('td', {}, tagChips(file.tags)),
    h('td', {}, statusBadge(file.status)),
    h('td', { class: 'actions-col' }, h('div', { class: 'cell-actions' }, ...actions)),
  );
}

function downloadFile(file) {
  const a = h('a', { href: `/api/files/${file.id}/download`, download: file.filename });
  document.body.append(a);
  a.click();
  a.remove();
}

async function deployFile(file) {
  try {
    await api(`/api/files/${file.id}/deploy`, { method: 'POST', body: { force: false } });
    toast('File deployed', 'ok');
    await load();
  } catch (e) {
    if (e.status === 409) await resolveFileConflict(file);
    else toastError(e);
  }
}

async function resolveFileConflict(file) {
  const r = await confirmAction({
    title: 'Local conflict',
    message: `Local file “${file.filename}” does not match the vault.`,
    confirmText: 'Overwrite local',
    danger: true,
    extra: { label: 'Adopt local changes' },
  });
  if (r.extra) {
    try {
      await api(`/api/files/${file.id}/adopt-local`, { method: 'POST', body: {} });
      toast('Local changes adopted', 'ok');
      await load();
    } catch (e) { toastError(e); }
  } else if (r.ok) {
    try {
      await api(`/api/files/${file.id}/deploy`, { method: 'POST', body: { force: true } });
      toast('Local file overwritten', 'ok');
      await load();
    } catch (e) { toastError(e); }
  }
}

async function undeployFile(file) {
  const r = await confirmAction({
    title: 'Remove local file',
    message: `~/.ssh/${file.filename} will be deleted. The definition will remain in the vault.`,
    confirmText: 'Remove local',
    danger: true,
  });
  if (!r.ok) return;
  try {
    await api(`/api/files/${file.id}/undeploy`, { method: 'POST', body: { force: true } });
    toast('Local file deleted', 'ok');
    await load();
  } catch (e) { toastError(e); }
}

async function deleteFile(file) {
  const r = await confirmAction({
    title: 'Delete file from vault',
    message: `“${file.filename}” will be deleted from the encrypted vault.`,
    confirmText: 'Delete',
    danger: true,
    checkLabel: 'Also delete local file',
    checkDefault: false,
  });
  if (!r.ok) return false;
  try {
    await api(`/api/files/${file.id}?local=${r.checked ? '1' : '0'}`, { method: 'DELETE' });
    toast('File deleted', 'ok');
    await load();
    return true;
  } catch (e) { toastError(e); return false; }
}

/* ------------------------------------------------------------------ */
/* Bulk actions                                                        */
/* ------------------------------------------------------------------ */

async function bulkDeploy(kind) {
  const items = selectedOf(kind);
  if (!items.length) return;
  let ok = 0;
  const errors = [];
  for (const item of items) {
    try {
      await api(`/api/${kind}/${item.id}/deploy`, { method: 'POST', body: kind === 'hosts' ? {} : { force: false } });
      ok++;
    } catch (e) { errors.push(labelOf(kind, item) + ': ' + e.message); }
  }
  toast(`${ok} deployed${errors.length ? `, ${errors.length} failed` : ''}`, errors.length ? 'err' : 'ok');
  if (errors.length) console.warn(errors);
  state.selection.clear();
  await load();
}

async function bulkUndeploy(kind) {
  const items = selectedOf(kind);
  if (!items.length) return;
  const r = await confirmAction({
    title: 'Remove local',
    message: `${plural(items.length, 'entry', 'entries')} will be deleted from ~/.ssh. The definitions will remain in the vault.`,
    confirmText: 'Remove local',
    danger: true,
  });
  if (!r.ok) return;
  let ok = 0;
  let failed = 0;
  for (const item of items) {
    try {
      await api(`/api/${kind}/${item.id}/undeploy`, { method: 'POST', body: kind === 'hosts' ? {} : { force: true } });
      ok++;
    } catch { failed++; }
  }
  toast(`${ok} removed${failed ? `, ${failed} failed` : ''}`, failed ? 'err' : 'ok');
  state.selection.clear();
  await load();
}

async function bulkDelete(kind) {
  const items = selectedOf(kind);
  if (!items.length) return;
  const r = await confirmAction({
    title: 'Delete from vault',
    message: `${plural(items.length, 'entry', 'entries')} will be deleted from the encrypted vault.${kind === 'keys' ? ' Keys used by hosts will be removed from those hosts.' : ''}`,
    confirmText: 'Delete',
    danger: true,
    checkLabel: 'Also delete locally',
    checkDefault: false,
  });
  if (!r.ok) return;
  let ok = 0;
  let failed = 0;
  for (const item of items) {
    try {
      const q = kind === 'hosts' ? '' : `?local=${r.checked ? '1' : '0'}&force=1`;
      await api(`/api/${kind}/${item.id}${q}`, { method: 'DELETE' });
      ok++;
    } catch { failed++; }
  }
  toast(`${ok} deleted${failed ? `, ${failed} failed` : ''}`, failed ? 'err' : 'ok');
  state.selection.clear();
  await load();
}

function labelOf(kind, item) {
  if (kind === 'keys') return item.alias;
  if (kind === 'hosts') return item.patterns.join(' ');
  return item.filename;
}

/* ------------------------------------------------------------------ */
/* Modals + confirmations                                              */
/* ------------------------------------------------------------------ */

function openModal({ title, subtitle, body, footer = [], size = '' }) {
  closeAllRowDropdowns();
  const dialog = $('#modal');
  if (dialog.open) dialog.close();
  dialog.className = `modal ${size}`.trim();
  const article = h('article', { class: 'modal-card' });
  const bodyEl = h('div', { class: 'modal-body' }, body);
  const foot = h('footer', { class: 'modal-foot' }, ...footer);
  article.append(
    h('header', { class: 'modal-head' },
      h('h2', { text: title }),
      subtitle ? h('p', { text: subtitle }) : null,
    ),
    bodyEl,
    foot,
  );
  dialog.replaceChildren(article);
  dialog.onclick = (e) => { if (e.target === dialog) dialog.close(); };
  dialog.showModal();
  return {
    dialog,
    bodyEl,
    foot,
    close: () => dialog.close(),
    error: (msg) => {
      let el = bodyEl.querySelector('.form-error');
      if (!el) {
        el = h('p', { class: 'form-error', role: 'alert' });
        bodyEl.prepend(el);
      }
      el.textContent = msg;
    },
  };
}

function modalFooter(cancelText, onCancel, saveLabel, onSave, extra = [], left = []) {
  const save = btn(saveLabel, null, async () => {
    save.disabled = true;
    const old = save.querySelector('span')?.textContent;
    if (save.querySelector('span')) save.querySelector('span').textContent = 'Saving…';
    try { await onSave(); }
    finally {
      save.disabled = false;
      if (save.querySelector('span') && old) save.querySelector('span').textContent = old;
    }
  }, 'btn primary');
  return [...left, h('div', { class: 'spacer' }), ...extra, btn(cancelText, null, onCancel, 'btn'), save];
}

function confirmAction({ title, message, confirmText = 'Confirm', cancelText = 'Cancel', danger = false, checkLabel = null, checkDefault = false, extra = null }) {
  closeAllRowDropdowns();
  return new Promise((resolve) => {
    const dialog = $('#confirm');
    if (dialog.open) dialog.close();
    let settled = false;
    const done = (result) => {
      if (settled) return;
      settled = true;
      dialog.close();
      resolve(result);
    };
    const checkbox = checkLabel ? h('input', { type: 'checkbox', class: 'checkbox', checked: checkDefault }) : null;
    const article = h('article', { class: 'modal-card' },
      h('header', { class: 'modal-head' }, h('h2', { text: title })),
      h('div', { class: 'modal-body' },
        h('p', { class: 'prewrap', style: { margin: 0, color: 'var(--text-2)' }, text: message }),
        checkbox ? h('label', { class: 'inline', style: { marginTop: '4px' } }, checkbox, h('span', { text: checkLabel })) : null,
      ),
      h('footer', { class: 'modal-foot' },
        h('div', { class: 'spacer' }),
        extra ? btn(extra.label, null, () => done({ ok: false, checked: checkbox?.checked || false, extra: true }), 'btn') : null,
        btn(cancelText, null, () => done({ ok: false, checked: checkbox?.checked || false, extra: false }), 'btn'),
        btn(confirmText, null, () => done({ ok: true, checked: checkbox?.checked || false, extra: false }), danger ? 'btn danger' : 'btn primary'),
      ));
    dialog.replaceChildren(article);
    dialog.onclick = (e) => { if (e.target === dialog) done({ ok: false, checked: false, extra: false }); };
    dialog.onclose = () => { if (!settled) { settled = true; resolve({ ok: false, checked: false, extra: false }); } };
    dialog.showModal();
  });
}

function openWarnings(title, warnings, description = '', extraActions = []) {
  const m = openModal({
    title,
    body: h('div', { class: 'flex-col gap-8' },
      description ? h('p', { class: 'text-sm muted', style: { margin: '0 0 4px' }, text: description }) : null,
      ...warnings.map((w) => h('div', { class: 'banner warn', text: w })),
    ),
    footer: [h('div', { class: 'spacer' }), ...extraActions, btn('Close', null, () => m.close(), 'btn')],
  });
  return m;
}

/* ------------------------------------------------------------------ */
/* Key forms                                                           */
/* ------------------------------------------------------------------ */

function keyStatusNote(status) {
  if (!status || status.state === 'deployed' || status.state === 'not_deployed') return null;
  return h('div', { class: `banner ${status.state === 'drift' || status.state === 'blocked' ? 'danger' : 'warn'}` },
    icon('alert'),
    h('span', { text: status.message || status.state }),
  );
}

function certificatePanel(cert) {
  return h('div', { class: 'form-section' },
    h('h3', { class: 'form-section-title', text: 'OpenSSH certificate' }),
    h('div', { class: 'inline wrap', style: { marginBottom: '10px' } },
      h('span', { class: `badge ${cert.expired ? 'danger' : cert.notYetValid ? 'warn' : 'ok'}`, text: cert.expired ? 'expired' : cert.notYetValid ? 'not yet valid' : 'valid' }),
      h('span', { class: 'muted text-xs', text: `${cert.certType} · key id ${cert.keyId || '—'}` }),
    ),
    h('dl', { class: 'kv' },
      h('dt', { text: 'Certificate fingerprint' }), h('dd', { class: 'mono', text: cert.fingerprint || '—' }),
      h('dt', { text: 'Valid from' }), h('dd', { text: fmtDate(cert.validAfter) }),
      h('dt', { text: 'Valid until' }), h('dd', { text: fmtDate(cert.validBefore) }),
      h('dt', { text: 'Principals' }), h('dd', { text: (cert.principals || []).join(', ') || '—' }),
    ),
  );
}

function generateControls(commentValue, onGenerated) {
  const alg = h('select', { class: 'select' },
    h('option', { value: 'ed25519', text: 'ed25519' }),
    h('option', { value: 'rsa', text: 'RSA' }),
    h('option', { value: 'ecdsa', text: 'ECDSA' }),
  );
  const bits = h('select', { class: 'select' },
    h('option', { value: '3072', text: '3072 bits' }),
    h('option', { value: '4096', text: '4096 bits' }),
    h('option', { value: '2048', text: '2048 bits' }),
  );
  const updateBits = () => {
    bits.replaceChildren();
    if (alg.value === 'rsa') {
      ['2048', '3072', '4096'].forEach((n) => bits.append(h('option', { value: n, text: `${n} bits` })));
      bits.value = '3072';
    } else if (alg.value === 'ecdsa') {
      ['256', '384', '521'].forEach((n) => bits.append(h('option', { value: n, text: `${n} bits` })));
      bits.value = '256';
    } else {
      bits.append(h('option', { value: '0', text: 'Ed25519 (256 bits)' }));
      bits.value = '0';
    }
  };
  alg.addEventListener('change', updateBits);
  updateBits();
  const generateBtn = btn('Generate pair', 'refresh', async () => {
    generateBtn.disabled = true;
    try {
      const res = await api('/api/generate', {
        method: 'POST',
        body: { algorithm: alg.value, bits: Number(bits.value) || 0, comment: commentValue() },
      });
      onGenerated(res);
      toast('Key pair generated', 'ok');
    } catch (e) { toastError(e); }
    finally { generateBtn.disabled = false; }
  }, 'btn');
  return h('div', { class: 'form-section' },
    h('h3', { class: 'form-section-title', text: 'Generate a new pair' }),
    h('div', { class: 'inline wrap' }, alg, bits, generateBtn),
    h('p', { class: 'hint', text: 'The private key will be stored inside the encrypted vault. You can also paste an existing key.' }),
  );
}

async function openKeyEditor(key) {
  let raw = null;
  if (key) {
    const m = openModal({
      title: 'Edit key',
      subtitle: 'Loading encrypted material…',
      body: h('div', { class: 'empty' }, h('span', { class: 'spinner' })),
      footer: [h('div', { class: 'spacer' }), btn('Cancel', null, () => m.close(), 'btn')],
    });
    try {
      raw = await api(`/api/keys/${key.id}`);
      m.close();
    } catch (e) { m.close(); toastError(e); return; }
  }
  renderKeyForm(key, raw);
}

function renderKeyForm(summary, raw) {
  const isNew = !summary;
  const key = raw?.key || null;
  const status = raw?.status || summary?.status || null;
  const info = summary?.info;
  const infoError = summary?.infoError;
  const deployed = !isNew && status?.state !== 'not_deployed';
  const errorEl = h('p', { class: 'form-error', role: 'alert' });
  const alias = h('input', { class: 'input', value: key?.alias || summary?.alias || '', placeholder: 'github', autocomplete: 'off' });
  const filename = h('input', { class: 'input mono', value: key?.filename || summary?.filename || '', placeholder: 'id_github (optional)', disabled: deployed });
  const tags = h('input', { class: 'input', value: tagsText(key?.tags || summary?.tags), placeholder: 'work, git' });
  const comment = h('input', { class: 'input', value: key?.comment || summary?.comment || '', placeholder: 'github@sshvault' });
  const pub = h('textarea', { class: 'textarea mono', rows: 4, value: key?.publicKey || summary?.publicKey || '', placeholder: 'ssh-ed25519 AAAA…' });
  const priv = h('textarea', { class: 'textarea mono', rows: 9, value: key?.privateKey || '', placeholder: '-----BEGIN OPENSSH PRIVATE KEY-----' });
  const cert = h('textarea', { class: 'textarea mono', rows: 5, value: key?.certificate || summary?.certificate || '', placeholder: 'ssh-ed25519-cert-v01@openssh.com AAAA…' });
  const deploy = h('input', { type: 'checkbox', class: 'checkbox', checked: true });

  const body = h('div', { class: 'flex-col gap-16' },
    errorEl,
    !isNew ? keyStatusNote(status) : null,
    infoError ? h('div', { class: 'banner warn' }, icon('alert'), h('span', { text: infoError })) : null,
    info?.cert ? certificatePanel(info.cert) : null,
    h('div', { class: 'form-grid' },
      field('Alias', alias, 'Display name used inside the app.'),
      field('Local filename', filename, isNew ? 'Leave empty to use id_<alias>.' : (deployed ? 'Remove the local deployment before renaming.' : 'Filename inside ~/.ssh.')),
      field('Tags', tags, 'Comma-separated.'),
      field('Comment', comment),
    ),
    !isNew ? h('div', { class: 'inline wrap' },
      h('span', { class: 'badge info', text: key?.kind || summary?.kind || 'key' }),
      h('span', { class: 'fingerprint', text: key?.fingerprint || summary?.fingerprint || 'no fingerprint' }),
    ) : null,
    generateControls(() => comment.value.trim() || alias.value.trim(), (res) => {
      priv.value = res.privateKey;
      pub.value = res.publicKey;
      cert.value = '';
    }),
    h('div', { class: 'form-section' },
      h('h3', { class: 'form-section-title', text: 'Key material' }),
      field('Public key', pub),
      field('Private key', priv),
      field('Certificate', cert),
      !isNew ? h('div', { class: 'sensitive-note' }, icon('alert'), h('span', { text: 'The private key is shown in plain text in this form. Do not close the tab on a shared machine.' })) : null,
    ),
    isNew ? h('label', { class: 'inline' }, deploy, h('span', { text: 'Create the files in ~/.ssh on save' })) : null,
  );

  const m = openModal({
    title: isNew ? 'New key' : `Key · ${summary.alias}`,
    subtitle: isNew ? 'Add a key or certificate to the vault.' : 'View or edit all key details.',
    body,
    size: 'wide',
    footer: modalFooter('Cancel', () => m.close(), isNew ? 'Create key' : 'Save changes', async () => {
      errorEl.textContent = '';
      if (!alias.value.trim()) { errorEl.textContent = 'Alias is required.'; return; }
      const payload = {
        revision: state.data.vault.revision,
        alias: alias.value.trim(),
        filename: filename.value.trim(),
        tags: parseTags(tags.value),
        comment: comment.value.trim(),
        publicKey: pub.value,
        privateKey: priv.value,
        certificate: cert.value,
        kind: '',
      };
      if (isNew) payload.deploy = deploy.checked;
      await submitKey(m, errorEl, summary, payload, isNew);
    }, [],
      isNew ? [] : [btn('Delete', 'trash', async () => {
        if (await deleteKey(summary)) m.close();
      }, 'btn danger')]),
  });
}

async function submitKey(m, errorEl, summary, payload, isNew, force = false) {
  try {
    const body = { ...payload };
    if (!isNew) body.force = force;
    const res = await api(isNew ? '/api/keys' : `/api/keys/${summary.id}`, {
      method: isNew ? 'POST' : 'PATCH',
      body,
    });
    m.close();
    toast(isNew ? 'Key created' : 'Key updated', 'ok');
    if (res.warning) toast(res.warning, 'err');
    await load();
  } catch (e) {
    if (!isNew && e.status === 409 && e.code === 'conflict') {
      const r = await confirmAction({
        title: 'Local conflict',
        message: 'Local files have changed since you opened the editor. Overwrite them with the vault version?',
        confirmText: 'Overwrite local',
        danger: true,
        extra: { label: 'Adopt local and discard this change' },
      });
      if (r.ok) return submitKey(m, errorEl, summary, payload, isNew, true);
      if (r.extra) {
        try {
          await api(`/api/keys/${summary.id}/adopt-local`, { method: 'POST', body: {} });
          m.close();
          toast('Local changes adopted', 'ok');
          await load();
        } catch (e2) { toastError(e2); }
      }
      return;
    }
    await handleFormError(m, errorEl, e);
  }
}

async function handleFormError(m, errorEl, e) {
  if (e.code === 'revision') {
    toast('The vault changed; reloading…', 'err');
    m.close();
    await load();
    return;
  }
  errorEl.textContent = e.message || String(e);
}

/* ------------------------------------------------------------------ */
/* Host form                                                           */
/* ------------------------------------------------------------------ */

const COMMON_OPTIONS = [
  'ProxyJump', 'ProxyCommand', 'IdentitiesOnly', 'AddKeysToAgent', 'ForwardAgent',
  'ServerAliveInterval', 'ServerAliveCountMax', 'ConnectTimeout', 'ConnectionAttempts',
  'ControlMaster', 'ControlPath', 'ControlPersist', 'Compression', 'TCPKeepAlive',
  'StrictHostKeyChecking', 'UserKnownHostsFile', 'LogLevel', 'LocalForward',
  'RemoteForward', 'DynamicForward', 'RequestTTY', 'SendEnv', 'SetEnv',
  'PreferredAuthentications', 'PubkeyAuthentication', 'PasswordAuthentication',
  'HostKeyAlgorithms', 'KexAlgorithms', 'Ciphers', 'MACs', 'BindAddress', 'IPQoS',
  'GatewayPorts', 'ExitOnForwardFailure', 'PermitLocalCommand', 'LocalCommand',
  'RemoteCommand', 'CertificateFile',
];

function openHostEditor(host) {
  const isNew = !host;
  const errorEl = h('p', { class: 'form-error', role: 'alert' });
  const patterns = h('input', { class: 'input mono', value: (host?.patterns || []).join(', '), placeholder: 'github, *.example.com' });
  const hostname = h('input', { class: 'input', value: host?.hostname || '', placeholder: 'github.com' });
  const user = h('input', { class: 'input', value: host?.user || '', placeholder: 'git' });
  const port = h('input', { class: 'input', type: 'number', min: 1, max: 65535, value: host?.port || '', placeholder: '22' });
  const deploy = h('input', { type: 'checkbox', class: 'checkbox', checked: isNew });

  const keyList = h('div', { class: 'check-list' });
  const selectedKeys = new Set(host?.identityKeyIds || []);
  if (!state.data.keys.length) {
    keyList.append(h('span', { class: 'muted text-sm', text: 'No keys in the vault.' }));
  } else {
    for (const key of [...state.data.keys].sort((a, b) => a.alias.localeCompare(b.alias))) {
      const cb = h('input', {
        type: 'checkbox',
        class: 'checkbox',
        checked: selectedKeys.has(key.id),
        onchange: (e) => {
          if (e.target.checked) selectedKeys.add(key.id);
          else selectedKeys.delete(key.id);
          updatePreview();
        },
      });
      keyList.append(h('label', { class: 'check-item' }, cb, h('span', { text: key.alias }), h('span', { class: 'sub', text: key.filename })));
    }
  }

  const optionsBox = h('div', { class: 'flex-col gap-8' });
  const addOption = (name = '', value = '') => {
    const row = h('div', { class: 'option-row' });
    const nameInput = h('input', { class: 'input mono', value: name, list: 'common-options', placeholder: 'ProxyJump' });
    const valueInput = h('input', { class: 'input mono', value, placeholder: 'bastion' });
    const remove = iconBtn('x', 'Remove option', () => { row.remove(); updatePreview(); });
    nameInput.addEventListener('input', () => updatePreview());
    valueInput.addEventListener('input', () => updatePreview());
    row.append(nameInput, valueInput, remove);
    optionsBox.append(row);
  };
  (host?.options || []).forEach((o) => addOption(o.name, o.value));

  const datalist = h('datalist', { id: 'common-options' }, ...COMMON_OPTIONS.map((o) => h('option', { value: o })));
  let preview = h('pre', { class: 'code' });

  const updatePreview = () => {
    const lines = [];
    const pats = splitPatterns(patterns.value);
    lines.push('Host ' + (pats.join(' ') || '<host>'));
    if (hostname.value.trim()) lines.push('    HostName ' + hostname.value.trim());
    if (user.value.trim()) lines.push('    User ' + user.value.trim());
    const p = Number(port.value);
    if (p && p !== 22) lines.push('    Port ' + p);
    for (const id of selectedKeys) {
      const key = state.data.keys.find((k) => k.id === id);
      if (key) lines.push('    IdentityFile ' + localPath(key.filename));
    }
    optionsBox.querySelectorAll('.option-row').forEach((row) => {
      const inputs = row.querySelectorAll('input');
      const n = inputs[0].value.trim();
      const v = inputs[1].value.trim();
      if (n) lines.push('    ' + n + (v ? ' ' + v : ''));
    });
    preview.textContent = lines.join('\n');
  };

  [patterns, hostname, user, port].forEach((el) => el.addEventListener('input', updatePreview));

  const body = h('div', { class: 'flex-col gap-16' },
    errorEl,
    !isNew ? h('div', { class: 'inline wrap' },
      h('span', { class: 'muted text-xs', text: 'Local status' }),
      statusBadge(host.status),
    ) : null,
    h('div', { class: 'form-grid' },
      field('Host', patterns, 'One or more comma-separated patterns.'),
      field('HostName', hostname),
      field('User', user),
      field('Port', port, 'Leave empty or use 22 for the default.'),
    ),
    h('div', { class: 'form-section' },
      h('h3', { class: 'form-section-title', text: 'IdentityFile' }),
      keyList,
      selectedKeys.size ? null : h('p', { class: 'hint', text: 'Without an IdentityFile, ssh will use its default configuration.' }),
    ),
    h('div', { class: 'form-section' },
      h('div', { class: 'inline' },
        h('h3', { class: 'form-section-title mb-0', text: 'Advanced options' }),
        h('div', { class: 'spacer' }),
        btn('Add option', 'plus', () => { addOption(); updatePreview(); }, 'btn sm'),
      ),
      datalist,
      optionsBox,
      h('p', { class: 'hint', text: 'HostName, User, Port, Host, Match, Include, and IdentityFile have dedicated fields.' }),
    ),
    h('div', { class: 'form-section' },
      h('h3', { class: 'form-section-title', text: 'Preview' }),
      preview,
    ),
    isNew ? h('label', { class: 'inline' }, deploy, h('span', { text: 'Create the entry in ~/.ssh/config on save' })) : null,
  );

  const m = openModal({
    title: isNew ? 'New host' : `Edit host · ${host.patterns.join(' ')}`,
    subtitle: 'The managed block is placed at the top of ~/.ssh/config so it takes precedence.',
    body,
    size: 'wide',
    footer: modalFooter('Cancel', () => m.close(), isNew ? 'Create host' : 'Save changes', async () => {
      errorEl.textContent = '';
      const options = [];
      optionsBox.querySelectorAll('.option-row').forEach((row) => {
        const inputs = row.querySelectorAll('input');
        const name = inputs[0].value.trim();
        const value = inputs[1].value.trim();
        if (name) options.push({ name, value });
      });
      const payload = {
        revision: state.data.vault.revision,
        patterns: splitPatterns(patterns.value),
        hostname: hostname.value.trim(),
        user: user.value.trim(),
        port: Number(port.value) || 0,
        identityKeyIds: [...selectedKeys],
        options,
        deploy: isNew ? deploy.checked : false,
        force: false,
      };
      if (!payload.patterns.length) { errorEl.textContent = 'Host is required.'; return; }
      try {
        const res = await api(isNew ? '/api/hosts' : `/api/hosts/${host.id}`, { method: isNew ? 'POST' : 'PATCH', body: payload });
        m.close();
        toast(isNew ? 'Host created' : 'Host updated', 'ok');
        if (res.warning) toast(res.warning, 'err');
        await load();
      } catch (e) {
        if (e.status === 409 && e.code === 'conflict') {
          const r = await confirmAction({
            title: 'Config conflict',
            message: 'The managed block changed outside the app. Overwrite it with the vault version?',
            confirmText: 'Overwrite',
            danger: true,
          });
          if (!r.ok) return;
          try {
            const res = await api(isNew ? '/api/hosts' : `/api/hosts/${host.id}`, { method: isNew ? 'POST' : 'PATCH', body: { ...payload, force: true } });
            m.close();
            toast('Host saved and synchronized', 'ok');
            if (res.warning) toast(res.warning, 'err');
            await load();
          } catch (e2) { await handleFormError(m, errorEl, e2); }
          return;
        }
        await handleFormError(m, errorEl, e);
      }
    }, [], isNew ? [] : [btn('Delete', 'trash', async () => {
      if (await deleteHost(host)) m.close();
    }, 'btn danger')]),
  });
  updatePreview();
}

function splitPatterns(value) {
  const out = [];
  const seen = new Set();
  for (const p of String(value || '').split(/[\s,]+/)) {
    const t = p.trim();
    if (!t || seen.has(t)) continue;
    seen.add(t);
    out.push(t);
  }
  return out;
}

function localPath(filename) {
  const dir = state.data?.sshDir || '~/.ssh';
  if (dir.endsWith('/.ssh')) return `~/.ssh/${filename}`;
  return `${dir.replace(/\/$/, '')}/${filename}`;
}

/* ------------------------------------------------------------------ */
/* File form                                                           */
/* ------------------------------------------------------------------ */

async function openFileEditor(file) {
  let raw = null;
  if (file) {
    const m = openModal({
      title: 'Edit file',
      subtitle: 'Loading…',
      body: h('div', { class: 'empty' }, h('span', { class: 'spinner' })),
      footer: [h('div', { class: 'spacer' }), btn('Cancel', null, () => m.close(), 'btn')],
    });
    try {
      raw = await api(`/api/files/${file.id}/raw`);
      m.close();
    } catch (e) { m.close(); toastError(e); return; }
  }
  const data = raw?.file;
  const status = raw?.status;
  const isNew = !data;
  const errorEl = h('p', { class: 'form-error', role: 'alert' });
  const filename = h('input', { class: 'input mono', value: data?.filename || '', placeholder: 'known_hosts' });
  const description = h('input', { class: 'input', value: data?.description || '', placeholder: 'Optional description' });
  const tags = h('input', { class: 'input', value: tagsText(data?.tags), placeholder: 'work, ssh' });
  const mode = h('select', { class: 'select' },
    ['0600', '0640', '0644'].map((m) => h('option', { value: m, text: m })),
  );
  mode.value = data ? modeString(data.mode) : '0600';
  const deploy = h('input', { type: 'checkbox', class: 'checkbox', checked: isNew });

  let encoding = data?.encoding || 'utf8';
  let content = data?.content || '';
  const textArea = h('textarea', { class: 'textarea mono', rows: 12, value: encoding === 'utf8' ? content : '', hidden: encoding === 'base64' });
  const binaryNote = h('div', { class: 'file-drop', hidden: encoding !== 'base64' },
    h('div', { class: 'inline' }, icon('file'), h('strong', { text: 'Binary file' }), h('span', { class: 'muted', id: 'binary-size' })),
    h('p', { class: 'hint', text: 'You can download it or replace it by uploading another file.' }),
  );
  const fileInput = h('input', { type: 'file', hidden: true });
  const uploadBtn = btn('Upload file', 'upload', () => fileInput.click(), 'btn');
  fileInput.addEventListener('change', async () => {
    const f = fileInput.files?.[0];
    if (!f) return;
    const buffer = await f.arrayBuffer();
    if (buffer.byteLength > 4 * 1024 * 1024) { errorEl.textContent = 'File exceeds the 4 MiB limit.'; return; }
    const text = decodeText(buffer);
    if (text !== null) {
      encoding = 'utf8';
      content = text;
      textArea.value = text;
      textArea.hidden = false;
      binaryNote.hidden = true;
      if (!filename.value) filename.value = f.name;
    } else {
      encoding = 'base64';
      content = toBase64(buffer);
      textArea.hidden = true;
      binaryNote.hidden = false;
      $('#binary-size').textContent = fmtSize(buffer.byteLength);
      if (!filename.value) filename.value = f.name;
    }
    fileInput.value = '';
  });
  const downloadBtn = data ? btn('Download', 'download', () => downloadFile(data), 'btn') : null;

  const body = h('div', { class: 'flex-col gap-16' },
    errorEl,
    !isNew ? h('div', { class: 'inline wrap' },
      h('span', { class: 'muted text-xs', text: 'Local status' }),
      statusBadge(status),
    ) : null,
    file?.sensitive ? h('div', { class: 'sensitive-note' }, icon('alert'), h('span', { text: 'This file controls host access or verification. Edit it carefully.' })) : null,
    h('div', { class: 'form-grid' },
      field('Name', filename, 'Relative path inside ~/.ssh.'),
      field('Permissions', mode),
      field('Description', description),
      field('Tags', tags, 'Comma-separated.'),
    ),
    h('div', { class: 'form-section' },
      h('div', { class: 'inline' }, h('h3', { class: 'form-section-title mb-0', text: 'Content' }), h('div', { class: 'spacer' }), uploadBtn, downloadBtn),
      fileInput,
      binaryNote,
      textArea,
    ),
    isNew ? h('label', { class: 'inline' }, deploy, h('span', { text: 'Create the file in ~/.ssh on save' })) : null,
  );

  const m = openModal({
    title: isNew ? 'New file' : `Edit · ${data.filename}`,
    subtitle: 'Files live inside the encrypted vault and are projected to ~/.ssh.',
    body,
    size: 'wide',
    footer: modalFooter('Cancel', () => m.close(), isNew ? 'Create file' : 'Save changes', async () => {
      errorEl.textContent = '';
      if (!filename.value.trim()) { errorEl.textContent = 'Filename is required.'; return; }
      const payload = {
        revision: state.data.vault.revision,
        filename: filename.value.trim(),
        description: description.value.trim(),
        tags: parseTags(tags.value),
        encoding,
        content: encoding === 'utf8' ? textArea.value : content,
        mode: parseInt(mode.value, 8),
        deploy: isNew ? deploy.checked : false,
        force: false,
      };
      try {
        const res = await api(isNew ? '/api/files' : `/api/files/${data.id}`, { method: isNew ? 'POST' : 'PATCH', body: payload });
        m.close();
        toast(isNew ? 'File created' : 'File updated', 'ok');
        if (res.warning) toast(res.warning, 'err');
        await load();
      } catch (e) {
        if (e.status === 409 && e.code === 'conflict') {
          const r = await confirmAction({
            title: 'Local conflict',
            message: 'The local file changed. Overwrite it with the vault version?',
            confirmText: 'Overwrite local',
            danger: true,
            extra: { label: 'Adopt local changes' },
          });
          if (r.extra) {
            try {
              await api(`/api/files/${data.id}/adopt-local`, { method: 'POST', body: {} });
              m.close();
              toast('Local changes adopted', 'ok');
              await load();
            } catch (e2) { toastError(e2); }
            return;
          }
          if (!r.ok) return;
          try {
            const res = await api(`/api/files/${data.id}`, { method: 'PATCH', body: { ...payload, force: true } });
            m.close();
            toast('File saved and synchronized', 'ok');
            if (res.warning) toast(res.warning, 'err');
            await load();
          } catch (e2) { await handleFormError(m, errorEl, e2); }
          return;
        }
        await handleFormError(m, errorEl, e);
      }
    }, [], isNew ? [] : [btn('Delete', 'trash', async () => {
      if (await deleteFile(data)) m.close();
    }, 'btn danger')]),
  });
}

/* ------------------------------------------------------------------ */
/* Import + config                                                     */
/* ------------------------------------------------------------------ */

async function openImport() {
  const m = openModal({
    title: 'Import from ~/.ssh',
    subtitle: 'Scanning the folder…',
    body: h('div', { class: 'empty' }, h('span', { class: 'spinner' })),
    footer: [h('div', { class: 'spacer' }), btn('Cancel', null, () => m.close(), 'btn')],
  });
  let scan;
  try { scan = await api('/api/import/scan'); }
  catch (e) { m.close(); toastError(e); return; }
  const subtitle = m.dialog.querySelector('.modal-head p');
  if (subtitle) subtitle.textContent = 'Review what you want to add to the vault. Nothing is changed until you confirm.';

  const items = scan.items || [];
  const selected = new Set(items.filter((i) => !i.conflict).map((i) => i.tempId));
  const groups = { key: [], host: [], file: [] };
  for (const item of items) groups[item.kind]?.push(item);

  const applyBtn = btn('Import', 'download', null, 'btn primary');
  const updateApply = () => {
    applyBtn.querySelector('span').textContent = `Import ${selected.size}`;
    applyBtn.disabled = selected.size === 0;
  };
  applyBtn.addEventListener('click', async () => {
    applyBtn.disabled = true;
    try {
      const res = await api('/api/import/apply', { method: 'POST', body: { revision: state.data.vault.revision, ids: [...selected] } });
      m.close();
      const imp = res.imported || {};
      toast(`Imported ${imp.keys || 0} keys, ${imp.hosts || 0} hosts, and ${imp.files || 0} files`, 'ok');
      if (res.warnings?.length) openWarnings('Import warnings', res.warnings);
      await load();
    } catch (e) { applyBtn.disabled = false; toastError(e); }
  });
  updateApply();

  const body = h('div', { class: 'flex-col gap-16' });
  if (scan.warnings?.length) {
    body.append(h('div', { class: 'banner warn' }, icon('alert'), h('div', { class: 'flex-col gap-8' }, ...scan.warnings.map((w) => h('span', { text: w })))));
  }
  if (!items.length) {
    body.append(emptyState('search', 'Nothing to import', 'No keys, hosts, or files found in ~/.ssh.'));
  }
  for (const [kind, label] of [['key', 'Keys'], ['host', 'Hosts'], ['file', 'Files']]) {
    const list = groups[kind];
    if (!list.length) continue;
    body.append(h('div', { class: 'section-title' }, h2Text(label), h('span', { class: 'muted', text: plural(list.length, 'entry', 'entries') })));
    for (const item of list) body.append(importItemRow(item, selected, updateApply));
  }
  if (scan.unmanaged?.length) {
    body.append(h('div', { class: 'section-title' }, h2Text('Unmanaged'), h('span', { class: 'muted', text: plural(scan.unmanaged.length, 'item', 'items') })));
    const panel = h('article', { class: 'panel' });
    for (const u of scan.unmanaged) {
      panel.append(h('div', { class: 'setting-row' },
        h('div', { class: 'setting-text' }, h('h3', { class: 'mono', text: u.name }), h('p', { text: u.reason })),
      ));
    }
    body.append(panel);
  }

  m.bodyEl.replaceChildren(body);
  m.foot.replaceChildren(
    h('div', { class: 'spacer' }),
    btn('All', null, () => { items.filter((i) => !i.conflict).forEach((i) => selected.add(i.tempId)); rerenderImport(body, groups, selected, updateApply); updateApply(); }, 'btn sm ghost'),
    btn('None', null, () => { selected.clear(); rerenderImport(body, groups, selected, updateApply); updateApply(); }, 'btn sm ghost'),
    btn('Cancel', null, () => m.close(), 'btn'),
    applyBtn,
  );
}

function h2Text(text) { return h('h2', { text }); }

function rerenderImport(container, groups, selected, update) {
  // Rebuild only the selection-aware rows by triggering a light DOM refresh.
  const rows = container.querySelectorAll('[data-import-id]');
  rows.forEach((row) => {
    const id = row.dataset.importId;
    const cb = row.querySelector('input[type=checkbox]');
    if (cb) cb.checked = selected.has(id);
  });
  update();
}

function importItemRow(item, selected, update) {
  const disabled = Boolean(item.conflict);
  const cb = h('input', {
    type: 'checkbox',
    class: 'checkbox',
    checked: selected.has(item.tempId),
    disabled,
    onchange: (e) => {
      if (e.target.checked) selected.add(item.tempId);
      else selected.delete(item.tempId);
      update();
    },
  });
  let title = item.filename || item.patterns?.join(' ') || '';
  let details = [];
  if (item.kind === 'key') {
    details.push(item.alias, item.fingerprint || 'no fingerprint');
    if (item.hasPrivate) details.push('private');
    if (item.hasPublic) details.push('public');
    if (item.hasCert) details.push('cert');
  } else if (item.kind === 'host') {
    details.push([item.user, item.hostname].filter(Boolean).join('@') || 'no hostname');
    if (item.identityFiles?.length) details.push(item.identityFiles.join(', '));
    if (item.options?.length) details.push(plural(item.options.length, 'option', 'options'));
  } else {
    details.push(fmtSize(item.size || 0), modeString(item.mode));
    if (item.sensitive) details.push('sensitive');
    if (item.encoding === 'base64') details.push('binary');
  }
  const row = h('label', { class: 'check-item import-row', dataset: { importId: item.tempId } },
    cb,
    h('div', { class: 'cell-stack' },
      h('div', { class: 'inline wrap' },
        h('strong', { class: item.kind === 'file' ? 'mono' : '', text: title }),
        item.conflict ? h('span', { class: 'badge danger', text: 'Already exists' }) : null,
        item.warnings?.length ? h('span', { class: 'badge warn', text: plural(item.warnings.length, 'warning', 'warnings') }) : null,
      ),
      h('span', { class: 'sub', text: details.filter(Boolean).join(' · ') }),
      item.warnings?.length ? h('span', { class: 'sub warn-text', text: item.warnings[0] }) : null,
    ),
  );
  return row;
}

async function openConfigPreview() {
  try {
    const res = await api('/api/config/preview');
    const m = openModal({
      title: '~/.ssh/config preview',
      subtitle: 'Managed block at the top of the file. The rest is not modified.',
      body: h('pre', { class: 'code', style: { maxHeight: '60vh' }, text: res.config || '# (empty)' }),
      size: 'wide',
      footer: [h('div', { class: 'spacer' }),
        btn('Copy', 'copy', () => copyText(res.config || '', 'Config copied'), 'btn'),
        btn('Close', null, () => m.close(), 'btn')],
    });
  } catch (e) { toastError(e); }
}

async function openDuplicates() {
  const m = openModal({
    title: 'Resolve duplicates',
    subtitle: 'Loading duplicate blocks…',
    body: h('div', { class: 'empty' }, h('span', { class: 'spinner' })),
    footer: [h('div', { class: 'spacer' }), btn('Close', null, () => m.close(), 'btn')],
    size: 'wide',
  });
  let report;
  try {
    report = await api('/api/config/duplicates');
  } catch (e) { m.close(); toastError(e); return; }
  if (!report.items?.length) {
    m.close();
    toast('No pending duplicates', 'ok');
    return;
  }
  const sub = m.dialog.querySelector('.modal-head p');
  if (sub) sub.textContent = 'Confirm each block separately. A backup is made before writing.';
  const wiz = { report, skipped: new Set(), stats: { commented: 0, removed: 0, kept: 0 } };

  const renderStep = () => {
    const pending = wiz.report.items.filter((i) => !wiz.skipped.has(i.id));
    if (!pending.length) { renderSummary(); return; }
    const item = pending[0];
    const err = h('p', { class: 'form-error', role: 'alert' });
    const body = h('div', { class: 'flex-col gap-16' },
      err,
      h('div', { class: 'inline wrap' },
        h('span', { class: 'badge warn', text: `Pending ${pending.length}` }),
        h('span', { class: 'muted text-xs', text: `lines ${item.startLine}–${item.endLine}` }),
      ),
      h('div', { class: 'flex-col gap-8' },
        h('h3', { class: 'form-section-title', text: 'Duplicate patterns' }),
        h('div', { class: 'tags' }, ...item.patterns.map((p) => h('span', { class: 'tag accent', text: p }))),
        item.mixed ? h('p', { class: 'hint', text: 'The outer block has more patterns. You can keep the ones that are not duplicated.' }) : null,
      ),
      h('div', { class: 'split-2' },
        h('div', { class: 'flex-col gap-8' },
          h('h3', { class: 'form-section-title', text: 'Outer block' }),
          h('pre', { class: 'code', text: item.external }),
        ),
        h('div', { class: 'flex-col gap-8' },
          h('h3', { class: 'form-section-title', text: 'Managed block' }),
          h('pre', { class: 'code', text: item.managed }),
        ),
      ),
      h('p', { class: 'hint', text: 'The managed block is at the top of ~/.ssh/config and takes precedence. Commenting out is reversible; deleting asks for confirmation and makes a backup.' }),
    );
    m.bodyEl.replaceChildren(body);

    const doAction = async (action) => {
      if (action === 'remove') {
        const c = await confirmAction({
          title: 'Delete old block',
          message: `The outer block for ${item.patterns.join(', ')} will be deleted. A backup will be saved in ~/.ssh/.sshvault-backups.`,
          confirmText: 'Delete block',
          danger: true,
        });
        if (!c.ok) return;
      }
      try {
        const res = await api('/api/config/duplicates/resolve', {
          method: 'POST',
          body: { configHash: wiz.report.configHash, id: item.id, action },
        });
        if (action === 'comment') wiz.stats.commented++;
        else if (action === 'remove') wiz.stats.removed++;
        wiz.report = res;
        renderStep();
      } catch (e) {
        if (e.code === 'config_changed') {
          try {
            wiz.report = await api('/api/config/duplicates');
            wiz.skipped.clear();
            renderStep();
            toast('Config changed; list updated', 'err');
          } catch (e2) { err.textContent = e2.message || String(e2); }
          return;
        }
        err.textContent = e.message || String(e);
      }
    };

    const keep = btn('Keep', null, () => {
      wiz.skipped.add(item.id);
      wiz.stats.kept++;
      renderStep();
    }, 'btn ghost');
    const exit = btn('Exit', null, async () => { m.close(); await load(); }, 'btn ghost');
    const split = item.mixed ? btn('Keep non-duplicates', 'filter', () => doAction('split'), 'btn') : null;
    const remove = btn('Delete', 'trash', () => doAction('remove'), 'btn danger');
    const comment = btn('Comment out', 'check', () => doAction('comment'), 'btn primary');
    m.foot.replaceChildren(...[h('div', { class: 'spacer' }), keep, exit, split, remove, comment].filter(Boolean));
  };

  const renderSummary = () => {
    const body = h('div', { class: 'flex-col gap-12' },
      h('p', { class: 'text-sm muted', style: { margin: 0 }, text: 'Session summary:' }),
      h('div', { class: 'tags' },
        h('span', { class: 'tag', text: `${wiz.stats.commented} commented out` }),
        h('span', { class: 'tag', text: `${wiz.stats.removed} deleted` }),
        h('span', { class: 'tag', text: `${wiz.stats.kept} kept` }),
      ),
      h('p', { class: 'hint', text: 'Kept duplicates will keep appearing in the warning until you resolve or delete them.' }),
    );
    m.bodyEl.replaceChildren(body);
    m.foot.replaceChildren(h('div', { class: 'spacer' }), btn('Close', null, async () => { m.close(); await load(); }, 'btn primary'));
  };

  renderStep();
}

/* ------------------------------------------------------------------ */
/* Settings                                                            */
/* ------------------------------------------------------------------ */

function renderSettings() {
  const root = $('#view');
  root.replaceChildren();
  const vault = state.data.vault;
  const info = h('dl', { class: 'kv' },
    h('dt', { text: 'File' }), h('dd', { class: 'mono', text: vault.path }),
    h('dt', { text: 'Revision' }), h('dd', { text: String(vault.revision) }),
    h('dt', { text: 'Created' }), h('dd', { text: fmtDate(vault.createdAt) }),
    h('dt', { text: 'Updated' }), h('dd', { text: fmtDate(vault.updatedAt) }),
    h('dt', { text: 'SSH directory' }), h('dd', { class: 'mono', text: state.data.sshDir }),
    h('dt', { text: 'Version' }), h('dd', { text: state.data.version }),
  );

  const defaultVaultPath = state.data.defaultVaultPath;
  const isDefaultVault = Boolean(defaultVaultPath) && state.data.vault.path === defaultVaultPath;
  const remember = h('input', { type: 'checkbox', checked: Boolean(state.data.rememberVault) });
  remember.addEventListener('change', async () => {
    remember.disabled = true;
    try {
      const res = await api('/api/preferences', {
        method: 'POST',
        body: { rememberVault: remember.checked },
      });
      state.data.rememberVault = Boolean(res.rememberVault);
      toast(res.rememberVault ? 'Last vault will be remembered' : 'Last vault will not be remembered', 'ok');
    } catch (e) {
      remember.checked = !remember.checked;
      toastError(e);
    } finally {
      remember.disabled = false;
    }
  });

  const security = h('article', { class: 'panel' },
    h('header', { class: 'panel-head' }, icon('shield'), h('h2', { text: 'Security' })),
    h('div', { class: 'setting-row' },
      h('div', { class: 'setting-text' }, h('h3', { text: 'Idle lock' }), h('p', { text: 'The vault locks itself and discards the derived key from memory.' })),
      h('span', { class: 'badge info', text: fmtDuration(state.data.lockAfterSeconds) }),
    ),
    h('div', { class: 'setting-row' },
      h('div', { class: 'setting-text' }, h('h3', { text: 'Vault password' }), h('p', { text: 'Re-encrypts the file with a new password and a new salt.' })),
      btn('Change password', 'lock', openChangePassword, 'btn'),
    ),
    h('div', { class: 'setting-row' },
      h('div', { class: 'setting-text' }, h('h3', { text: 'Lock now' }), h('p', { text: 'Closes the web session until you enter the password again.' })),
      btn('Lock', 'lock', lockNow, 'btn'),
    ),
    defaultVaultPath && !isDefaultVault
      ? h('div', { class: 'setting-row' },
        h('div', { class: 'setting-text' }, h('h3', { text: 'Open default vault' }), h('p', { class: 'mono', text: defaultVaultPath })),
        btn('Open default', 'folder', openDefaultVault, 'btn'),
      )
      : null,
    h('div', { class: 'setting-row' },
      h('div', { class: 'setting-text' }, h('h3', { text: 'Open existing vault' }), h('p', { text: 'Switch to another sshvault file on this machine.' })),
      btn('Open…', 'folder', openExistingVault, 'btn'),
    ),
    h('div', { class: 'setting-row' },
      h('div', { class: 'setting-text' }, h('h3', { text: 'Create new vault' }), h('p', { text: 'Start a new encrypted vault at another path.' })),
      btn('Create…', 'plus', openNewVault, 'btn'),
    ),
    h('div', { class: 'setting-row' },
      h('div', { class: 'setting-text' }, h('h3', { text: 'Remember last vault' }), h('p', { text: 'Open the last successfully unlocked vault on startup. Only the path is stored, never the password.' })),
      h('label', { class: 'switch' }, remember, h('span', { text: 'Enabled' })),
    ),
  );

  const tools = h('article', { class: 'panel' },
    h('header', { class: 'panel-head' }, icon('upload'), h('h2', { text: 'Import and review' })),
    h('div', { class: 'setting-row' },
      h('div', { class: 'setting-text' }, h('h3', { text: 'Scan ~/.ssh' }), h('p', { text: 'Finds keys, hosts, and files that are not in the vault yet.' })),
      btn('Scan', 'refresh', openImport, 'btn'),
    ),
    h('div', { class: 'setting-row' },
      h('div', { class: 'setting-text' }, h('h3', { text: '~/.ssh/config' }), h('p', { text: 'Preview the managed block without writing anything.' })),
      btn('View config', 'file', openConfigPreview, 'btn'),
    ),
    h('div', { class: 'setting-row' },
      h('div', { class: 'setting-text' }, h('h3', { text: 'Config duplicates' }), h('p', { text: 'Review Hosts defined both inside and outside the managed block, one at a time.' })),
      btn('Review', 'alert', openDuplicates, 'btn'),
    ),
    (state.data.internalFiles || []).length
      ? h('div', { class: 'setting-row' },
        h('div', { class: 'setting-text' }, h('h3', { text: 'Internal entries' }), h('p', { text: `${plural(state.data.internalFiles.length, 'hidden entry', 'hidden entries')} point to the vault or its sidecars.` })),
        btn('Clear', 'trash', cleanupInternalFiles, 'btn'),
      )
      : null,
  );

  const themeSelect = h('select', { class: 'select' },
    h('option', { value: '', text: 'System' }),
    h('option', { value: 'light', text: 'Light' }),
    h('option', { value: 'dark', text: 'Dark' }),
  );
  themeSelect.value = state.theme;
  themeSelect.addEventListener('change', () => setTheme(themeSelect.value));

  const appearance = h('article', { class: 'panel' },
    h('header', { class: 'panel-head' }, icon('eye'), h('h2', { text: 'Appearance' })),
    h('div', { class: 'setting-row' },
      h('div', { class: 'setting-text' }, h('h3', { text: 'Theme' }), h('p', { text: 'Saved only in this browser.' })),
      themeSelect,
    ),
  );

  const about = h('article', { class: 'panel' },
    h('header', { class: 'panel-head' }, icon('shield'), h('h2', { text: 'How it works' })),
    h('p', { class: 'text-sm muted', style: { margin: '0 0 10px' }, text: 'All vault content is encrypted with Argon2id and XChaCha20-Poly1305. The password is not stored on disk. Files in ~/.ssh are the local projection of the entries you choose to deploy.' }),
    h('p', { class: 'text-sm muted', style: { margin: 0 }, text: 'Without the password there is no recovery. Vault backups are encrypted too. If you work on a shared server, lock the vault when you are not using it.' }),
  );

  root.append(
    h('article', { class: 'panel' }, h('header', { class: 'panel-head' }, icon('file'), h('h2', { text: 'Vault' })), info),
    security,
    tools,
    appearance,
    about,
  );
}

async function openChangePassword() {
  const errorEl = h('p', { class: 'form-error', role: 'alert' });
  const current = h('input', { class: 'input', type: 'password', autocomplete: 'current-password' });
  const next = h('input', { class: 'input', type: 'password', autocomplete: 'new-password' });
  const confirm = h('input', { class: 'input', type: 'password', autocomplete: 'new-password' });
  const body = h('div', { class: 'flex-col gap-16' },
    errorEl,
    field('Current password', current),
    field('New password', next, 'At least 8 characters.'),
    field('Confirm new password', confirm),
  );
  const m = openModal({
    title: 'Change password',
    body,
    footer: modalFooter('Cancel', () => m.close(), 'Change password', async () => {
      errorEl.textContent = '';
      if (next.value.length < 8) { errorEl.textContent = 'The new password must be at least 8 characters.'; return; }
      if (next.value !== confirm.value) { errorEl.textContent = 'Passwords do not match.'; return; }
      try {
        await api('/api/password', { method: 'POST', body: { current: current.value, next: next.value } });
        m.close();
        toast('Password changed', 'ok');
      } catch (e) { await handleFormError(m, errorEl, e); }
    }),
  });
}

async function lockNow() {
  try {
    await api('/api/lock', { method: 'POST', body: {} });
    showLock();
  } catch (e) { toastError(e); }
}

function setTheme(theme) {
  state.theme = theme || '';
  if (state.theme) document.documentElement.dataset.theme = state.theme;
  else delete document.documentElement.dataset.theme;
  localStorage.setItem('sshvault-theme', state.theme);
  if (state.view === 'settings') renderSettings();
}

function applyTheme() {
  if (state.theme) document.documentElement.dataset.theme = state.theme;
}

/* ------------------------------------------------------------------ */
/* Lock screen                                                         */
/* ------------------------------------------------------------------ */

let lockSequence = 0;

async function showLock() {
  const seq = ++lockSequence;
  closeAllPopovers();
  closeAllRowDropdowns();
  closeModalSafe();
  const dialog = $('#confirm');
  if (dialog.open) dialog.close();
  $('#lock').hidden = false;
  $('#unlock-error').textContent = '';
  let session = null;
  try { session = await api('/api/session'); } catch { /* keep the generic lock screen */ }
  if (seq !== lockSequence) return;
  state.needsSetup = Boolean(session?.needsSetup);
  state.canPickVault = Boolean(session?.canPickVault);
  const setup = state.needsSetup;
  $('#lock-title').textContent = setup ? 'Create vault' : 'Vault locked';
  $('#lock-description').textContent = setup
    ? 'The vault file does not exist yet. Set a password to create it.'
    : 'Enter the vault password to continue.';
  $('#confirm-field').hidden = !setup;
  $('#unlock-password').value = '';
  $('#unlock-confirm').value = '';
  $('#unlock-password').autocomplete = setup ? 'new-password' : 'current-password';
  $('#unlock-submit').textContent = setup ? 'Create vault' : 'Unlock';
  setTimeout(() => $('#unlock-password')?.focus(), 30);
}

function hideLock() {
  $('#lock').hidden = true;
  $('#unlock-password').value = '';
  $('#unlock-confirm').value = '';
  $('#confirm-field').hidden = true;
  $('#unlock-error').textContent = '';
  state.needsSetup = false;
}

function closeModalSafe() {
  const modal = $('#modal');
  if (modal.open) modal.close();
}

async function unlockSubmit(e) {
  e.preventDefault();
  const input = $('#unlock-password');
  const confirm = $('#unlock-confirm');
  const error = $('#unlock-error');
  const submit = $('#unlock-submit');
  const setup = state.needsSetup;
  error.textContent = '';
  if (setup) {
    if (input.value.length < 8) { error.textContent = 'The password must be at least 8 characters.'; return; }
    if (input.value !== confirm.value) { error.textContent = 'Passwords do not match.'; return; }
  }
  submit.disabled = true;
  submit.textContent = setup ? 'Creating…' : 'Unlocking…';
  try {
    if (setup) {
      await api('/api/setup', { method: 'POST', body: { password: input.value } });
      state.needsSetup = false;
      toast('Vault created', 'ok');
    } else {
      await api('/api/unlock', { method: 'POST', body: { password: input.value } });
      toast('Vault unlocked', 'ok');
    }
    hideLock();
    await load();
  } catch (err) {
    if (err.status === 429) error.textContent = 'Too many attempts. Wait a few seconds.';
    else if (err.status === 401) error.textContent = 'Incorrect password.';
    else if (err.code === 'vault_exists') error.textContent = 'The vault already exists. Try unlocking it instead.';
    else error.textContent = err.message || (setup ? 'Could not create the vault.' : 'Could not unlock.');
  } finally {
    submit.disabled = false;
    submit.textContent = state.needsSetup ? 'Create vault' : 'Unlock';
  }
}

async function openExistingVault() {
  await openVaultDialog('open');
}

async function openNewVault() {
  await openVaultDialog('new');
}

async function openDefaultVault() {
  const path = state.data?.defaultVaultPath;
  if (!path) return;
  try {
    await api('/api/vault/open', { method: 'POST', body: { path } });
    state.data = null;
    $('#shell').hidden = true;
    $('#boot').hidden = true;
    await showLock();
    toast('Default vault opened; enter its password.', 'ok');
  } catch (err) {
    if (err.code === 'vault_not_found') {
      toast(`Default vault not found: ${path}`, 'err');
    } else if (err.code === 'vault_empty') {
      toast('The default vault is empty. Use Create new vault to initialize it.', 'err');
    } else {
      toastError(err);
    }
  }
}

async function openVaultDialog(mode) {
  const isNew = mode === 'new';
  if (!state.canPickVault) {
    try {
      const session = await api('/api/session');
      state.canPickVault = Boolean(session?.canPickVault);
    } catch { /* locked is handled by api */ }
  }
  const pathInput = h('input', {
    class: 'input mono',
    placeholder: isNew ? '~/vaults/new.vault' : '~/.ssh/ssh.vault',
    autocomplete: 'off',
  });
  const browse = state.canPickVault
    ? btn('Browse…', 'folder', async () => {
      browse.disabled = true;
      try {
        const res = await api('/api/vault/pick', { method: 'POST', body: {} });
        if (res.path) pathInput.value = res.path;
      } catch (err) { m.error(err.message || String(err)); }
      finally { browse.disabled = false; }
    }, 'btn')
    : null;
  const action = btn(isNew ? 'Create' : 'Open', 'folder', async () => {
    const path = pathInput.value.trim();
    if (!path) { m.error('Vault path is required.'); return; }
    action.disabled = true;
    try {
      await api(isNew ? '/api/vault/new' : '/api/vault/open', { method: 'POST', body: { path } });
      m.close();
      state.data = null;
      $('#shell').hidden = true;
      $('#boot').hidden = true;
      await showLock();
      toast(isNew ? 'New vault path selected; set its password.' : 'Vault opened; enter its password.', 'ok');
    } catch (err) {
      if (!isNew && err.code === 'vault_empty') {
        m.error('This file is empty. Use Create new vault to initialize it.');
      } else if (!isNew && err.code === 'vault_not_found') {
        m.error('Vault not found. Use Create new vault to create one at this path.');
      } else {
        m.error(err.message || String(err));
      }
    } finally { action.disabled = false; }
  }, 'btn primary');
  const m = openModal({
    title: isNew ? 'Create new vault' : 'Open existing vault',
    subtitle: isNew
      ? 'Choose a new path. You will set its password next.'
      : 'Choose another sshvault file on this machine.',
    body: h('div', { class: 'flex-col gap-16' },
      state.data ? h('p', { class: 'hint', text: 'The current vault will be closed. Saved changes are kept.' }) : null,
      isNew ? h('p', { class: 'hint', text: 'The path may not exist or may be an empty file. Existing non-empty files are never overwritten.' }) : null,
      field('Vault path', pathInput, 'Absolute path or ~/…'),
      browse ? h('div', { class: 'inline wrap' }, browse, h('span', { class: 'hint', text: 'Use the native file picker.' })) : null,
    ),
    footer: [h('div', { class: 'spacer' }), btn('Cancel', null, () => m.close(), 'btn'), action],
  });
}

/* ------------------------------------------------------------------ */
/* Init + events                                                       */
/* ------------------------------------------------------------------ */

function bindEvents() {
  $$('.nav-item[data-view]').forEach((item) => {
    item.addEventListener('click', () => setView(item.dataset.view));
  });
  $('#lock-now').addEventListener('click', lockNow);
  $('#unlock-form').addEventListener('submit', unlockSubmit);
  $('#open-vault-lock').addEventListener('click', openExistingVault);
  $('#new-vault-lock').addEventListener('click', openNewVault);

  document.addEventListener('click', closeAllPopovers);
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeAllPopovers();
    if (e.key === '/' && !e.metaKey && !e.ctrlKey && !e.altKey) {
      const tag = document.activeElement?.tagName;
      if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return;
      e.preventDefault();
      $('.search-wrap input')?.focus();
    }
  });

  window.addEventListener('hashchange', () => {
    const view = location.hash.replace('#', '');
    if (view && view !== state.view) setView(view, false);
  });

  document.addEventListener('visibilitychange', async () => {
    if (document.visibilityState !== 'visible' || !state.data) return;
    try {
      const session = await api('/api/session');
      if (session.locked) showLock();
    } catch { /* locked is handled by api */ }
  });
}

function bootError(err) {
  const boot = $('#boot');
  boot.hidden = false;
  boot.replaceChildren(
    h('div', { class: 'empty' },
      h('div', { class: 'empty-mark' }, icon('alert', 'lg')),
      h('h3', { text: 'Could not open the vault' }),
      h('p', { text: err?.message || String(err) }),
      btn('Retry', 'refresh', () => location.reload(), 'btn primary'),
    ),
  );
}

async function init() {
  applyTheme();
  bindEvents();
  const hash = location.hash.replace('#', '');
  if (['keys', 'hosts', 'files', 'settings'].includes(hash)) state.view = hash;
  try {
    await load(true);
  } catch (e) {
    if (e.status === 423) {
      $('#boot').hidden = true;
      showLock();
      return;
    }
    bootError(e);
  }
}

init();
