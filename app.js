// Cyber Toolbox: semua logika berjalan di browser, tanpa backend atau telemetry.
// Request jaringan hanya ke layanan publik di README (tool 6-9) dan target yang Anda masukkan.
(() => {
  'use strict';

  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

  const REQUEST_TIMEOUT = 8000;
  const DOH_URL = 'https://cloudflare-dns.com/dns-query';
  const PROXY_RAW = 'https://api.allorigins.win/raw?url=';
  const PROXY_GET = 'https://api.allorigins.win/get?url=';

  // localStorage dibungkus try/catch: bisa diblokir (mode privat, file://, dsb.)
  const store = {
    get(key, fallback) {
      try {
        const raw = localStorage.getItem('ct:' + key);
        return raw === null ? fallback : JSON.parse(raw);
      } catch { return fallback; }
    },
    set(key, value) {
      try { localStorage.setItem('ct:' + key, JSON.stringify(value)); } catch { /* abaikan */ }
    },
    remove(key) {
      try { localStorage.removeItem('ct:' + key); } catch { /* abaikan */ }
    },
  };

  const HTML_ESC = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
  const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => HTML_ESC[c]);

  const unique = (arr) => [...new Set(arr)];

  let toastTimer;
  function toast(message) {
    const el = $('#toast');
    el.textContent = message;
    el.classList.add('show');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => el.classList.remove('show'), 1800);
  }

  // Salin ke clipboard, dengan fallback execCommand untuk konteks non-secure.
  async function copyText(text) {
    if (!text) { toast('Tidak ada yang disalin'); return; }
    try {
      await navigator.clipboard.writeText(text);
      toast('Disalin ke clipboard');
      return;
    } catch { /* lanjut ke fallback */ }
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.setAttribute('readonly', '');
    ta.style.cssText = 'position:fixed;top:0;left:0;opacity:0';
    document.body.appendChild(ta);
    ta.select();
    let ok = false;
    try { ok = document.execCommand('copy'); } catch { ok = false; }
    ta.remove();
    toast(ok ? 'Disalin ke clipboard' : 'Gagal menyalin, salin manual');
  }

  // Unduh teks sebagai file (dibuat lokal, tidak dikirim ke mana pun).
  function download(filename, content, mime) {
    const blob = new Blob([content], { type: mime + ';charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  // CSV dengan escaping + proteksi formula injection (=, +, -, @).
  function toCSV(rows) {
    return rows.map((row) => row.map((cell) => {
      let v = String(cell ?? '');
      if (/^[=+\-@\t\r]/.test(v)) v = "'" + v;
      return /[",\n\r]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v;
    }).join(',')).join('\r\n');
  }

  const stamp = () => new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-');

  /**
   * fetch dengan timeout (maks 8 detik) dan dukungan AbortSignal eksternal.
   * Selalu tanpa cookie dan tanpa referrer.
   */
  async function fetchWithTimeout(url, { timeout = REQUEST_TIMEOUT, signal, ...opts } = {}) {
    const ctrl = new AbortController();
    let timedOut = false;
    const timer = setTimeout(() => { timedOut = true; ctrl.abort(); }, Math.min(timeout, REQUEST_TIMEOUT));
    const onAbort = () => ctrl.abort();
    if (signal) {
      if (signal.aborted) ctrl.abort();
      else signal.addEventListener('abort', onAbort, { once: true });
    }
    try {
      return await fetch(url, { credentials: 'omit', referrerPolicy: 'no-referrer', ...opts, signal: ctrl.signal });
    } catch (err) {
      if (timedOut) throw new Error(`Timeout setelah ${Math.round(Math.min(timeout, REQUEST_TIMEOUT) / 1000)} detik`);
      if (signal && signal.aborted) throw new DOMException('Dibatalkan', 'AbortError');
      throw err;
    } finally {
      clearTimeout(timer);
      if (signal) signal.removeEventListener('abort', onAbort);
    }
  }

  function friendlyError(err) {
    if (!err) return 'Error tidak diketahui';
    if (err.name === 'AbortError') return 'Dibatalkan';
    if (err instanceof TypeError && /fetch|network|load/i.test(err.message)) {
      return navigator.onLine === false
        ? 'Perangkat sedang offline'
        : 'Gagal terhubung (jaringan, CORS, atau diblokir ekstensi/firewall)';
    }
    return err.message || String(err);
  }

  /** Query DNS via Cloudflare DoH (format JSON). */
  async function dohQuery(name, type = 'A', opts = {}) {
    const url = `${DOH_URL}?name=${encodeURIComponent(name)}&type=${type}`;
    const res = await fetchWithTimeout(url, { ...opts, headers: { Accept: 'application/dns-json' } });
    if (!res.ok) throw new Error(`DoH mengembalikan HTTP ${res.status}`);
    return res.json();
  }

  const DNS_RCODE = { 0: 'NOERROR', 1: 'FORMERR', 2: 'SERVFAIL', 3: 'NXDOMAIN', 4: 'NOTIMP', 5: 'REFUSED' };
  const answersOf = (data, type) => (data.Answer || []).filter((a) => a.type === type).map((a) => String(a.data).replace(/\.$/, ''));

  const IPV4_RE = /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;

  function isValidIPv6(s) {
    try { new URL(`http://[${s}]/`); return true; } catch { return false; }
  }

  const DOMAIN_RE = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})$/i;

  // Ekstensi file yang sering salah terbaca sebagai domain (mis. "setup.exe").
  const FILE_EXT = new Set(('exe dll sys bin bat cmd ps1 psm1 vbs vbe js jse wsf hta scr msi msp lnk jar class py pyc sh pl rb php ' +
    'asp aspx jsp html htm xhtml css json xml yaml yml ini cfg conf log txt csv tsv md rtf doc docx docm xls xlsx xlsm ppt pptx pdf ' +
    'png jpg jpeg gif bmp svg ico webp tif tiff mp3 mp4 wav avi mkv mov zip rar 7z gz tgz tar bz2 xz iso img dmg apk tmp dat bak db ' +
    'sqlite lock out dylib').split(' '));

  /** Pastikan string URL punya skema; kembalikan objek URL atau lempar error. */
  function toHttpUrl(raw) {
    let s = String(raw || '').trim();
    if (!s) throw new Error('Masukkan URL atau domain');
    if (/\s/.test(s)) throw new Error('URL tidak boleh mengandung spasi');
    if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) s = 'https://' + s;
    const u = new URL(s);
    if (!/^https?:$/.test(u.protocol)) throw new Error('Hanya mendukung http:// dan https://');
    // Chrome menerima host aneh tanpa error, jadi host divalidasi sendiri.
    const h = u.hostname;
    if (!(DOMAIN_RE.test(h) || IPV4_RE.test(h) || h.startsWith('[') || h === 'localhost')) {
      throw new Error(`Host "${h}" bukan domain atau IP yang valid`);
    }
    return u;
  }

  /** Normalisasi input domain: buang skema, path, port, dan titik di akhir. */
  function normalizeDomain(raw) {
    let s = String(raw || '').trim().toLowerCase();
    if (!s) return '';
    try {
      if (/^[a-z][a-z0-9+.-]*:\/\//.test(s)) s = new URL(s).hostname;
      else s = new URL('http://' + s).hostname; // juga mengubah IDN ke punycode
    } catch { /* biarkan validasi di bawah menolak */ }
    return s.replace(/\.$/, '').replace(/^\*\./, '');
  }

  function spinner(text) {
    return `<span class="inline-flex items-center gap-2 muted text-sm"><span class="spinner" aria-hidden="true"></span>${esc(text)}</span>`;
  }

  function alertBox(type, html) {
    return `<div class="alert alert-${type}">${html}</div>`;
  }

  function formatMs(ms) {
    return ms == null || Number.isNaN(ms) ? '–' : `${Math.round(ms)} ms`;
  }

  // Delegasi klik untuk semua tombol copy.
  document.addEventListener('click', (e) => {
    const direct = e.target.closest('[data-copy]');
    if (direct) { copyText(direct.dataset.copy); return; }
    const from = e.target.closest('[data-copy-from]');
    if (from) {
      const target = $(from.dataset.copyFrom);
      if (target) copyText(/^(INPUT|TEXTAREA)$/.test(target.tagName) ? target.value : target.textContent);
    }
  });

  // Tema (dark mode)
  function applyTheme(dark) {
    document.documentElement.classList.toggle('dark', dark);
    // Label tombol menyebut aksi berikutnya, ikon mengikuti.
    $('#themeLabel').textContent = dark ? 'Mode terang' : 'Mode gelap';
    $('#themeToggle .icon-moon').hidden = dark;
    $('#themeToggle .icon-sun').hidden = !dark;
  }

  applyTheme(document.documentElement.classList.contains('dark'));
  $('#themeToggle').addEventListener('click', () => {
    const dark = !document.documentElement.classList.contains('dark');
    applyTheme(dark);
    store.set('theme', dark ? 'dark' : 'light');
  });

  // Navigasi tab
  const tabButtons = $$('#tabbar [role="tab"]');
  const TAB_IDS = tabButtons.map((b) => b.dataset.tab);

  function activateTab(id, { focus = false } = {}) {
    if (!TAB_IDS.includes(id)) id = TAB_IDS[0];
    tabButtons.forEach((btn) => {
      const active = btn.dataset.tab === id;
      btn.setAttribute('aria-selected', String(active));
      btn.tabIndex = active ? 0 : -1;
      $('#panel-' + btn.dataset.tab).hidden = !active;
      if (active) {
        // Geser strip mobile secara manual: scrollIntoView ikut memindahkan titik awal tombol Tab.
        const nav = $('#tabbar');
        const r = btn.getBoundingClientRect(), nr = nav.getBoundingClientRect();
        if (r.left < nr.left || r.right > nr.right) nav.scrollLeft += r.left - nr.left - 16;
        if (focus) btn.focus();
      }
    });
    store.set('tab', id);
  }

  tabButtons.forEach((btn) => btn.addEventListener('click', () => activateTab(btn.dataset.tab)));
  $('#tabbar').addEventListener('keydown', (e) => {
    const idx = tabButtons.findIndex((b) => b.getAttribute('aria-selected') === 'true');
    let next = null;
    if (e.key === 'ArrowRight' || e.key === 'ArrowDown') next = (idx + 1) % tabButtons.length;
    else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') next = (idx - 1 + tabButtons.length) % tabButtons.length;
    else if (e.key === 'Home') next = 0;
    else if (e.key === 'End') next = tabButtons.length - 1;
    if (next !== null) {
      e.preventDefault();
      activateTab(TAB_IDS[next], { focus: true });
    }
  });

  // Angka 1-9 memilih alat, kecuali saat sedang mengetik di field.
  document.addEventListener('keydown', (e) => {
    if (e.altKey || e.ctrlKey || e.metaKey || !/^[1-9]$/.test(e.key)) return;
    const el = document.activeElement;
    if (el && (/^(INPUT|TEXTAREA|SELECT)$/.test(el.tagName) || el.isContentEditable)) return;
    activateTab(TAB_IDS[Number(e.key) - 1]);
  });

  // 1. IOC Extractor
  const IOC_TYPES = [
    ['ipv4', 'IPv4'], ['ipv6', 'IPv6'], ['url', 'URL'], ['domain', 'Domain'], ['email', 'Email'],
    ['md5', 'MD5'], ['sha1', 'SHA1'], ['sha256', 'SHA256'], ['cve', 'CVE'],
  ];

  const IOC_SAMPLE = `[Laporan insiden #2041: contoh data fiktif]
Phishing dari phish-desk@malicious-example[.]com mengarahkan korban ke
hxxps://login-secure-update[.]example[.]net/verify?id=8812 dan hxxp://203.0.113[.]45:8080/dl/invoice.zip

C2 terlihat di 198.51.100.7, 203.0.113.45 dan IPv6 2001:db8:85a3::8a2e:370:7334.
Host internal terdampak: 10.0.0.15, 192.168.1.20, fe80::1ff:fe23:4567:890a (abaikan jika filter private aktif).
Domain tambahan: cdn-update(.)evil-example(.)org, files.bad-actor.example

Hash payload:
MD5    d41d8cd98f00b204e9800998ecf8427e
SHA1   da39a3ee5e6b4b0d3255bfef95601890afd80709
SHA256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

Eksploitasi: CVE-2021-44228 (Log4Shell) dan cve-2023-4863. Dropper: setup.exe, run.ps1`;

  /** Ubah notasi defang umum kembali menjadi bentuk asli. */
  function refang(text) {
    return text
      .replace(/\bhxxp(s?)/gi, 'http$1')
      .replace(/\bfxp:\/\//gi, 'ftp://')
      .replace(/\[:\/\/\]/g, '://')
      .replace(/\[\s*(?:\.|dot)\s*\]|\(\s*(?:\.|dot)\s*\)|\{\s*(?:\.|dot)\s*\}/gi, '.')
      .replace(/\[\s*:\s*\]/g, ':')
      .replace(/\[\s*(?:@|at)\s*\]|\(\s*(?:@|at)\s*\)/gi, '@');
  }

  /** Defang sebuah IOC agar aman dibagikan (tidak bisa diklik). */
  function defang(type, value) {
    switch (type) {
      case 'url': {
        const m = value.match(/^([a-z][a-z0-9+.-]*):\/\/([^/?#]*)(.*)$/i);
        if (!m) return value;
        const scheme = m[1].replace(/^http/i, 'hxxp').replace(/^ftp/i, 'fxp');
        return `${scheme}://${m[2].replace(/\./g, '[.]')}${m[3]}`;
      }
      case 'domain':
      case 'ipv4': return value.replace(/\./g, '[.]');
      case 'email': return value.replace('@', '[@]').replace(/\.(?=[^.]*$)/, '[.]');
      case 'ipv6': return value.replace(/:/g, '[:]');
      default: return value;
    }
  }

  function isPrivateIPv4(ip) {
    const [a, b] = ip.split('.').map(Number);
    return a === 10 || a === 127 || a === 0 ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 169 && b === 254) ||
      (a === 100 && b >= 64 && b <= 127) ||
      a >= 224; // multicast & reserved
  }

  function isPrivateIPv6(ip) {
    const s = ip.toLowerCase();
    return s === '::1' || s === '::' || /^f[cd]/.test(s) || /^fe[89ab]/.test(s);
  }

  /** Ekstrak semua IOC dari teks; hasil per kategori tanpa duplikat. */
  function extractIOCs(text, { excludePrivate }) {
    const out = Object.fromEntries(IOC_TYPES.map(([k]) => [k, []]));

    // URL (buang tanda baca di akhir yang biasanya bagian dari kalimat)
    for (const m of text.matchAll(/\b(?:https?|ftp):\/\/[^\s"'<>`\\^{}|]+/gi)) {
      let u = m[0].replace(/[.,;:!?)\]}>'"]+$/, '');
      if (u.length > 10) out.url.push(u);
    }

    for (const m of text.matchAll(/\b[a-z0-9._%+-]+@(?:[a-z0-9-]+\.)+[a-z]{2,24}\b/gi)) {
      const tld = m[0].split('.').pop().toLowerCase();
      if (!FILE_EXT.has(tld)) out.email.push(m[0].toLowerCase());
    }

    for (const m of text.matchAll(/(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?!\.?\d)/g)) {
      if (!(excludePrivate && isPrivateIPv4(m[0]))) out.ipv4.push(m[0]);
    }

    // IPv6: kandidat longgar lalu divalidasi oleh parser URL bawaan browser
    for (const m of text.matchAll(/(?<![0-9a-z:.])(?:[0-9a-f]{0,4}:){2,7}(?:(?:\d{1,3}\.){3}\d{1,3}|[0-9a-f]{1,4})?(?![0-9a-z:])/gi)) {
      const v = m[0];
      const groups = v.split(':').filter(Boolean).length;
      if (v.length < 6 || groups < 2 || !isValidIPv6(v)) continue;
      if (!(excludePrivate && isPrivateIPv6(v))) out.ipv6.push(v.toLowerCase());
    }

    for (const m of text.matchAll(/\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,24}|xn--[a-z0-9-]{2,59})\b/gi)) {
      const d = m[0].toLowerCase();
      const tld = d.split('.').pop();
      if (!FILE_EXT.has(tld)) out.domain.push(d);
    }

    for (const [type, len] of [['md5', 32], ['sha1', 40], ['sha256', 64]]) {
      const re = new RegExp(`\\b[a-f0-9]{${len}}\\b`, 'gi');
      for (const m of text.matchAll(re)) out[type].push(m[0].toLowerCase());
    }

    for (const m of text.matchAll(/\bCVE-\d{4}-\d{4,7}\b/gi)) out.cve.push(m[0].toUpperCase());

    for (const k of Object.keys(out)) out[k] = unique(out[k]);
    return out;
  }

  let iocCurrent = {};

  function runIOC() {
    const raw = $('#iocInput').value;
    const doRefang = $('#iocRefang').checked;
    const doDefang = $('#iocDefang').checked;
    const text = doRefang ? refang(raw) : raw;
    const found = extractIOCs(text, { excludePrivate: $('#iocExcludePrivate').checked });

    iocCurrent = {};
    for (const [type] of IOC_TYPES) {
      iocCurrent[type] = found[type].map((v) => (doDefang ? defang(type, v) : v));
    }

    const total = Object.values(iocCurrent).reduce((n, arr) => n + arr.length, 0);
    $('#iocTotal').textContent = total ? `${total} indikator` : '';

    const box = $('#iocResults');
    if (!raw.trim()) {
      box.innerHTML = '<div class="empty">Tempel teks atau klik <strong>Load sample</strong>.</div>';
      return;
    }
    if (!total) {
      box.innerHTML = '<div class="empty">Tidak ada IOC yang ditemukan.</div>';
      return;
    }
    box.innerHTML = IOC_TYPES.filter(([type]) => iocCurrent[type].length).map(([type, label]) => `
      <div class="result-group">
        <div class="result-group-head">
          <span>${label} <span class="count">${iocCurrent[type].length}</span></span>
          <button type="button" class="copy-btn" data-copy="${esc(iocCurrent[type].join('\n'))}">Copy ${label}</button>
        </div>
        ${iocCurrent[type].map((v) => `
          <div class="result-row">
            <span class="value mono">${esc(v)}</span>
            <button type="button" class="copy-btn" data-copy="${esc(v)}" aria-label="Copy ${esc(v)}">Copy</button>
          </div>`).join('')}
      </div>`).join('');
  }

  function iocRows() {
    const rows = [];
    for (const [type, label] of IOC_TYPES) for (const v of iocCurrent[type] || []) rows.push([label, v]);
    return rows;
  }

  let iocDebounce;
  $('#iocInput').addEventListener('input', () => { clearTimeout(iocDebounce); iocDebounce = setTimeout(runIOC, 200); });
  ['#iocRefang', '#iocExcludePrivate', '#iocDefang'].forEach((s) => $(s).addEventListener('change', runIOC));
  $('#iocSample').addEventListener('click', () => { $('#iocInput').value = IOC_SAMPLE; runIOC(); });
  $('#iocClear').addEventListener('click', () => { $('#iocInput').value = ''; runIOC(); $('#iocInput').focus(); });
  $('#iocCopyAll').addEventListener('click', () => {
    const parts = IOC_TYPES.filter(([t]) => iocCurrent[t]?.length).map(([t, label]) => `# ${label}\n${iocCurrent[t].join('\n')}`);
    copyText(parts.join('\n\n'));
  });
  $('#iocCsv').addEventListener('click', () => {
    const rows = iocRows();
    if (!rows.length) return toast('Belum ada hasil');
    download(`ioc-${stamp()}.csv`, toCSV([['type', 'value'], ...rows]), 'text/csv');
  });
  $('#iocJson').addEventListener('click', () => {
    if (!iocRows().length) return toast('Belum ada hasil');
    const data = Object.fromEntries(IOC_TYPES.map(([t]) => [t, iocCurrent[t] || []]));
    download(`ioc-${stamp()}.json`, JSON.stringify(data, null, 2), 'application/json');
  });
  runIOC();

  // 2. Hash & Encode
  const utf8 = new TextEncoder();

  async function digestHex(algo, text) {
    const buf = await crypto.subtle.digest(algo, utf8.encode(text));
    return Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, '0')).join('');
  }

  // Base64 aman untuk UTF-8 (btoa saja hanya mendukung Latin-1).
  function base64Encode(str) {
    const bytes = utf8.encode(str);
    let bin = '';
    for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
    return btoa(bin);
  }

  function base64Decode(input) {
    let s = String(input).replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/');
    if (s.length % 4 === 1) throw new Error('Panjang Base64 tidak valid');
    while (s.length % 4) s += '=';
    let bin;
    try { bin = atob(s); } catch { throw new Error('Input bukan Base64 yang valid'); }
    const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
    return new TextDecoder('utf-8').decode(bytes);
  }

  let hashSeq = 0;
  async function updateHashes() {
    const text = $('#hashInput').value;
    const seq = ++hashSeq;
    $('#hashMeta').textContent = `${[...text].length} karakter · ${utf8.encode(text).length} byte`;
    const errBox = $('#hashError');
    if (!window.crypto || !crypto.subtle) {
      errBox.textContent = 'crypto.subtle tidak tersedia. Buka lewat https:// atau localhost, atau gunakan browser modern.';
      errBox.hidden = false;
      return;
    }
    try {
      const [s1, s256] = await Promise.all([digestHex('SHA-1', text), digestHex('SHA-256', text)]);
      if (seq !== hashSeq) return; // ada input lebih baru
      $('#hashSha1').value = s1;
      $('#hashSha256').value = s256;
      errBox.hidden = true;
    } catch (err) {
      errBox.textContent = 'Gagal menghitung hash: ' + friendlyError(err);
      errBox.hidden = false;
    }
  }

  const ENCODERS = {
    b64enc: ['Base64 encode', base64Encode],
    b64dec: ['Base64 decode', base64Decode],
    urlenc: ['URL encode', (s) => encodeURIComponent(s)],
    urldec: ['URL decode', (s) => {
      try { return decodeURIComponent(s); } catch { throw new Error('Urutan %XX tidak valid'); }
    }],
  };

  $$('[data-encode]').forEach((btn) => btn.addEventListener('click', () => {
    const [label, fn] = ENCODERS[btn.dataset.encode];
    const errBox = $('#encodeError');
    $('#encodeMode').textContent = '· ' + label;
    try {
      const result = fn($('#hashInput').value);
      $('#encodeOutput').value = result;
      errBox.hidden = true;
      if (btn.dataset.encode === 'b64dec' && result.includes('�')) {
        errBox.textContent = 'Peringatan: hasil berisi byte non-UTF-8 (kemungkinan data biner).';
        errBox.hidden = false;
      }
    } catch (err) {
      $('#encodeOutput').value = '';
      errBox.textContent = err.message;
      errBox.hidden = false;
    }
  }));

  $('#encodeSwap').addEventListener('click', () => {
    $('#hashInput').value = $('#encodeOutput').value;
    updateHashes();
  });
  $('#hashInput').addEventListener('input', updateHashes);
  updateHashes();

  // 3. JWT Decoder
  const b64url = (str) => base64Encode(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

  function sampleJWT() {
    const now = Math.floor(Date.now() / 1000);
    const header = { alg: 'HS256', typ: 'JWT' };
    const payload = { sub: '1234567890', name: 'Budi Santoso', role: 'analyst', iss: 'https://auth.example.com', aud: 'cyber-toolbox', iat: now, nbf: now, exp: now + 3600 };
    return `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}.c2lnbmF0dXJlLWNvbnRvaC10aWRhay12YWxpZA`;
  }

  function humanDuration(seconds) {
    const s = Math.abs(Math.round(seconds));
    const units = [['hari', 86400], ['jam', 3600], ['menit', 60], ['detik', 1]];
    const parts = [];
    let rest = s;
    for (const [name, size] of units) {
      const n = Math.floor(rest / size);
      if (n) { parts.push(`${n} ${name}`); rest -= n * size; }
      if (parts.length === 2) break;
    }
    return parts.join(' ') || '0 detik';
  }

  const fmtDate = (sec) => {
    const d = new Date(sec * 1000);
    return Number.isNaN(d.getTime()) ? 'tanggal tidak valid' : d.toLocaleString('id-ID', { dateStyle: 'medium', timeStyle: 'medium' });
  };

  function decodeJWT() {
    const raw = $('#jwtInput').value.trim().replace(/^Bearer\s+/i, '');
    const status = $('#jwtStatus');
    const resetViews = () => {
      $('#jwtHeader').textContent = '–';
      $('#jwtPayload').textContent = '–';
      $('#jwtClaims').innerHTML = '<p class="muted text-sm">Belum ada token.</p>';
    };
    if (!raw) { status.innerHTML = ''; resetViews(); return; }

    const parts = raw.split('.');
    if (parts.length === 5) { resetViews(); status.innerHTML = alertBox('error', 'Ini terlihat seperti JWE (token terenkripsi, 5 bagian). Payload tidak bisa dibaca tanpa kunci.'); return; }
    if (parts.length !== 3) { resetViews(); status.innerHTML = alertBox('error', `Format JWT tidak valid: harus 3 bagian dipisah titik, ditemukan ${parts.length}.`); return; }

    let header, payload;
    try { header = JSON.parse(base64Decode(parts[0])); } catch { resetViews(); status.innerHTML = alertBox('error', 'Header bukan Base64URL/JSON yang valid.'); return; }
    try { payload = JSON.parse(base64Decode(parts[1])); } catch { resetViews(); status.innerHTML = alertBox('error', 'Payload bukan Base64URL/JSON yang valid.'); return; }

    $('#jwtHeader').textContent = JSON.stringify(header, null, 2);
    $('#jwtPayload').textContent = JSON.stringify(payload, null, 2);

    const now = Date.now() / 1000;
    const notes = [];
    let pill;
    const exp = typeof payload.exp === 'number' ? payload.exp : null;
    const nbf = typeof payload.nbf === 'number' ? payload.nbf : null;

    if (nbf !== null && now < nbf) {
      pill = `<span class="pill pill-warn">Belum berlaku</span> <span class="text-sm muted">aktif dalam ${humanDuration(nbf - now)}</span>`;
    } else if (exp === null) {
      pill = '<span class="pill pill-warn">Tanpa klaim exp</span> <span class="text-sm muted">token tidak pernah kedaluwarsa</span>';
    } else if (now >= exp) {
      pill = `<span class="pill pill-bad">Expired</span> <span class="text-sm muted">${humanDuration(now - exp)} yang lalu</span>`;
    } else {
      pill = `<span class="pill pill-ok">Valid (belum expired)</span> <span class="text-sm muted">sisa ${humanDuration(exp - now)}</span>`;
    }

    const alg = String(header.alg || '');
    if (!alg || alg.toLowerCase() === 'none') notes.push('Algoritma <code>none</code>: token tanpa tanda tangan, jangan diterima oleh server.');
    if (!parts[2]) notes.push('Bagian signature kosong.');

    status.innerHTML = `<div class="flex flex-wrap items-center gap-2">${pill}<span class="badge badge-muted mono">alg: ${esc(alg || '–')}</span></div>` +
      (notes.length ? `<div class="mt-2">${alertBox('warn', notes.join('<br>'))}</div>` : '') +
      '<p class="muted text-xs mt-2">Status hanya berdasarkan jam perangkat Anda; signature tidak diverifikasi.</p>';

    const CLAIMS = { iss: 'Issuer', sub: 'Subject', aud: 'Audience', exp: 'Expires', nbf: 'Not before', iat: 'Issued at', jti: 'JWT ID' };
    const rows = Object.entries(CLAIMS).filter(([k]) => k in payload).map(([k, label]) => {
      let val = payload[k];
      let display = esc(typeof val === 'object' ? JSON.stringify(val) : val);
      if (['exp', 'nbf', 'iat'].includes(k) && typeof val === 'number') display += ` <span class="muted">(${esc(fmtDate(val))})</span>`;
      return `<tr><th scope="row"><span class="mono">${k}</span> · ${label}</th><td class="mono">${display}</td></tr>`;
    });
    $('#jwtClaims').innerHTML = rows.length
      ? `<div class="table-wrap"><table class="table"><tbody>${rows.join('')}</tbody></table></div>`
      : '<p class="muted text-sm">Tidak ada klaim terdaftar (iss, sub, aud, exp, nbf, iat, jti).</p>';
  }

  $('#jwtInput').addEventListener('input', decodeJWT);
  $('#jwtSample').addEventListener('click', () => { $('#jwtInput').value = sampleJWT(); decodeJWT(); });
  $('#jwtClear').addEventListener('click', () => { $('#jwtInput').value = ''; decodeJWT(); $('#jwtInput').focus(); });

  // 4. Password Generator
  const CHARSETS = {
    upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    lower: 'abcdefghijklmnopqrstuvwxyz',
    digits: '0123456789',
    symbols: '!@#$%^&*()-_=+[]{};:,.<>/?~|',
  };
  const AMBIGUOUS = /[Il1|O0o]/g;

  const WORDLIST = unique(`able acid actor adapt admit adult agent agree ahead alarm album alert alien alley allow alpha amber angle ankle apple april
arena argue arrow aside asset atlas audio audit avoid awake award badge baker bamboo banjo barn basic basin beach beard beast begin bench berry
bike bird blade blank blast blend bless blink block bloom board boat bonus boost booth brain brave bread brick bride brief bring brook brush
bubble bucket buddy build bunny cabin cable cactus camel camera candy canoe canvas cargo carpet carrot castle cedar chalk chair charm chart
chase cheek chef cherry chess chief chimney cider cinema circle civic clam claim clay clerk cliff climb clock cloud clover coach coast cobra
cocoa coffee comet coral cotton couch cougar cousin crane crater crayon creek crisp crown cube curve cycle daisy dance dawn delta denim depot
desert detail diary diesel dinner disco dock dolphin donkey dragon drama dream drift drum duck dune eagle early earth easel echo eclipse elbow
elder ember empty energy engine enjoy equal error essay ethic event exact exile fabric fairy falcon fancy farm feast fence ferry fever fiber
field final flag flame flash fleet flint float flock flute focus foggy forest fossil fox frame fresh frog frost fruit galaxy garden garlic
gecko gentle giant ginger glad glass globe glove goat gold grape grass gravel green grid grill guard guest guide guitar habit hammer harbor
harvest hatch hawk hazel heart hello helmet hero hiking hobby honey hope horse hotel humble hybrid igloo index inlet input iris island ivory
jacket jaguar jazz jelly jewel jolly judge juice jungle kayak kettle kidney kite kiwi koala ladder lake lamp lantern laptop lava lemon level
lilac lime linen lion liquid lizard llama lobby lobster locket lotus lucky lunar lunch magic magnet mango maple marble market meadow melon
mentor metal meteor middle mint mirror mobile model monkey moose mosaic motor mountain muffin museum music napkin nature nectar needle nest
noble noodle north novel nutmeg oasis ocean olive omega onion opera orange orbit orchid otter outer owl oxygen paddle palace panda paper
parade parrot pasta peach peanut pebble pelican pencil pepper piano pickle pilot pine pirate pixel planet plasma plaza plum poem polar pony
potato prism pulse puzzle quartz queen quest quiet quill rabbit radar radio rainbow raven razor ready recipe reef relay rhythm ribbon ridge
river robin robot rocket rodeo royal ruby rumble saddle safari salad salmon sandal saturn scarf school scout season seed shadow shelf shell
shield silver simple siren sketch slate sleet slope smile snack snow socket solar sonic spark spice spider spiral spoon spring squid stable
stamp star statue steam stone storm studio sugar summer sunset super surf swan sweet table taco talent tango teapot temple tennis thunder
ticket tiger timber toast tomato topaz torch tower tractor trail train tree tribe trophy tulip tundra turtle tuxedo twist umbrella unicorn
union unit urban valley vanilla velvet venus vessel violet violin vista vivid volcano voyage wafer wagon walnut walrus water wave wheat whale
willow window winter wizard wolf wombat yacht yellow yoga yogurt zebra zenith zero zipper zone`.split(/\s+/).filter(Boolean));

  /** Bilangan acak seragam [0, max) tanpa bias modulo (rejection sampling). */
  function randomInt(max) {
    const limit = Math.floor(0x100000000 / max) * max;
    const buf = new Uint32Array(1);
    let x;
    do { crypto.getRandomValues(buf); x = buf[0]; } while (x >= limit);
    return x % max;
  }

  function shuffle(arr) {
    for (let i = arr.length - 1; i > 0; i--) {
      const j = randomInt(i + 1);
      [arr[i], arr[j]] = [arr[j], arr[i]];
    }
    return arr;
  }

  function strengthOf(bits) {
    if (bits < 28) return [0, 'Sangat lemah'];
    if (bits < 36) return [1, 'Lemah'];
    if (bits < 60) return [2, 'Sedang'];
    if (bits < 80) return [3, 'Kuat'];
    return [4, 'Sangat kuat'];
  }

  // Estimasi waktu tebak rata-rata pada 10 miliar tebakan/detik (offline, hash cepat).
  function crackTime(bits) {
    const seconds = Math.pow(2, bits - 1) / 1e10;
    if (seconds < 1) return 'kurang dari 1 detik';
    if (seconds < 86400 * 365) return humanDuration(seconds);
    const years = seconds / (86400 * 365);
    if (years > 1e12) return 'lebih dari 1 triliun tahun';
    return `${years >= 1e6 ? years.toExponential(1) : Math.round(years).toLocaleString('id-ID')} tahun`;
  }

  function showPassword(value, bits, detail) {
    $('#pwOutput').value = value;
    const [level, label] = strengthOf(bits);
    $('#pwStrength').textContent = label;
    $('#pwEntropy').textContent = `≈ ${bits.toFixed(1)} bit entropi · ${detail}`;
    const meter = $('#pwMeter');
    meter.className = `progress mt-2 meter-${level}`;
    meter.setAttribute('aria-valuenow', String(Math.round(bits)));
    $('span', meter).style.width = Math.min(100, (bits / 128) * 100) + '%';
    $('#pwCrack').textContent = `Estimasi waktu tebak (10 miliar/detik): ${crackTime(bits)}`;
  }

  let lastMode = 'password';

  function generatePassword() {
    lastMode = 'password';
    const len = Number($('#pwLength').value);
    const noAmb = $('#pwNoAmbiguous').checked;
    const sets = [];
    if ($('#pwUpper').checked) sets.push(CHARSETS.upper);
    if ($('#pwLower').checked) sets.push(CHARSETS.lower);
    if ($('#pwDigits').checked) sets.push(CHARSETS.digits);
    if ($('#pwSymbols').checked) sets.push(CHARSETS.symbols);
    const pools = sets.map((s) => (noAmb ? s.replace(AMBIGUOUS, '') : s)).filter(Boolean);
    const err = $('#pwError');
    if (!pools.length) {
      err.textContent = 'Pilih minimal satu jenis karakter.';
      err.hidden = false;
      return;
    }
    err.hidden = true;
    const all = pools.join('');
    // Jamin minimal satu karakter dari tiap jenis yang dipilih, lalu acak urutannya.
    const chars = pools.map((p) => p[randomInt(p.length)]);
    while (chars.length < len) chars.push(all[randomInt(all.length)]);
    const bits = len * Math.log2(all.length);
    showPassword(shuffle(chars).join(''), bits, `${len} karakter dari ${all.length} simbol`);
  }

  function generatePassphrase() {
    lastMode = 'passphrase';
    const count = Math.min(12, Math.max(3, Number($('#ppWords').value) || 6));
    $('#ppWords').value = count;
    const sep = $('#ppSep').value;
    const words = Array.from({ length: count }, () => WORDLIST[randomInt(WORDLIST.length)]);
    const cased = $('#ppCap').checked ? words.map((w) => w[0].toUpperCase() + w.slice(1)) : words;
    let bits = count * Math.log2(WORDLIST.length);
    if ($('#ppNum').checked) {
      const i = randomInt(count);
      cased[i] += String(randomInt(10));
      bits += Math.log2(10 * count);
    }
    showPassword(cased.join(sep), bits, `${count} kata dari ${WORDLIST.length}`);
  }

  $('#ppInfo').textContent = `Wordlist bawaan: ${WORDLIST.length} kata (≈ ${Math.log2(WORDLIST.length).toFixed(1)} bit per kata).`;
  $('#pwLength').addEventListener('input', () => {
    $('#pwLengthVal').textContent = $('#pwLength').value;
    generatePassword();
  });
  ['#pwUpper', '#pwLower', '#pwDigits', '#pwSymbols', '#pwNoAmbiguous'].forEach((s) => $(s).addEventListener('change', generatePassword));
  ['#ppWords', '#ppSep', '#ppCap', '#ppNum'].forEach((s) => $(s).addEventListener('change', () => { if (lastMode === 'passphrase') generatePassphrase(); }));
  $('#pwGenerate').addEventListener('click', generatePassword);
  $('#ppGenerate').addEventListener('click', generatePassphrase);
  generatePassword();

  // 5. URL Inspector

  /** Decoder Punycode (RFC 3492) untuk menampilkan hostname IDN dalam Unicode. */
  function punycodeDecode(input) {
    const base = 36, tMin = 1, tMax = 26, skew = 38, damp = 700;
    const adapt = (delta, numPoints, first) => {
      let k = 0;
      delta = first ? Math.floor(delta / damp) : delta >> 1;
      delta += Math.floor(delta / numPoints);
      for (; delta > ((base - tMin) * tMax) >> 1; k += base) delta = Math.floor(delta / (base - tMin));
      return Math.floor(k + ((base - tMin + 1) * delta) / (delta + skew));
    };
    const digitOf = (c) => {
      if (c >= 48 && c <= 57) return c - 22; // 0-9 -> 26-35
      if (c >= 65 && c <= 90) return c - 65; // A-Z
      if (c >= 97 && c <= 122) return c - 97; // a-z
      return base;
    };
    const output = [];
    let n = 128, i = 0, bias = 72;
    let basic = input.lastIndexOf('-');
    if (basic < 0) basic = 0;
    for (let j = 0; j < basic; j++) output.push(input.charCodeAt(j));
    for (let idx = basic > 0 ? basic + 1 : 0; idx < input.length;) {
      const oldi = i;
      for (let w = 1, k = base; ; k += base) {
        if (idx >= input.length) throw new Error('Punycode tidak valid');
        const digit = digitOf(input.charCodeAt(idx++));
        if (digit >= base) throw new Error('Punycode tidak valid');
        i += digit * w;
        const t = k <= bias ? tMin : k >= bias + tMax ? tMax : k - bias;
        if (digit < t) break;
        w *= base - t;
      }
      const len = output.length + 1;
      bias = adapt(i - oldi, len, oldi === 0);
      n += Math.floor(i / len);
      i %= len;
      output.splice(i++, 0, n);
    }
    return String.fromCodePoint(...output);
  }

  function hostToUnicode(host) {
    return host.split('.').map((label) => {
      if (!label.toLowerCase().startsWith('xn--')) return label;
      try { return punycodeDecode(label.slice(4)); } catch { return label; }
    }).join('.');
  }

  // Skrip Unicode yang dicek untuk mendeteksi campuran (indikasi homograph).
  const SCRIPTS = [['Latin', /\p{Script=Latin}/u], ['Cyrillic', /\p{Script=Cyrillic}/u], ['Greek', /\p{Script=Greek}/u],
    ['Armenian', /\p{Script=Armenian}/u], ['Han', /\p{Script=Han}/u], ['Arabic', /\p{Script=Arabic}/u], ['Hebrew', /\p{Script=Hebrew}/u]];

  const DEFAULT_PORTS = { 'http:': '80', 'https:': '443', 'ftp:': '21', 'ws:': '80', 'wss:': '443' };

  function inspectUrl() {
    const raw = $('#urlInput').value.trim();
    const box = $('#urlResult');
    if (!raw) { box.innerHTML = '<div class="card empty">Masukkan URL untuk mulai.</div>'; return; }

    let input = raw, addedScheme = false;
    if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(raw) && !/^(mailto|javascript|data|tel|blob|about|file):/i.test(raw)) {
      input = 'http://' + raw;
      addedScheme = true;
    }
    let u;
    try { u = new URL(input); } catch {
      box.innerHTML = alertBox('error', 'URL tidak valid dan tidak bisa di-parse.');
      return;
    }

    const host = u.hostname;
    const unicodeHost = hostToUnicode(host);
    const isPuny = host.split('.').some((l) => l.toLowerCase().startsWith('xn--'));
    const nonAscii = unique([...raw].filter((c) => c.codePointAt(0) > 127));
    const https = u.protocol === 'https:';
    const isIp = IPV4_RE.test(host) || host.startsWith('[');
    const scripts = SCRIPTS.filter(([, re]) => re.test(unicodeHost)).map(([name]) => name);

    const warnings = [];
    if (addedScheme) warnings.push(['info', 'Skema tidak ditulis; diasumsikan <code>http://</code> untuk parsing.']);
    if (/^(javascript|data|vbscript):$/.test(u.protocol)) warnings.push(['error', `Skema <code>${esc(u.protocol)}</code> bisa mengeksekusi kode, berbahaya jika diklik.`]);
    if (/^(http|ws):$/.test(u.protocol)) warnings.push(['warn', 'Koneksi tidak terenkripsi (bukan HTTPS).']);
    if (isPuny) warnings.push(['warn', `Hostname memakai punycode (IDN). Tampilan Unicode: <strong class="mono">${esc(unicodeHost)}</strong>, waspadai homograph.`]);
    if (scripts.length > 1) warnings.push(['error', `Hostname mencampur skrip ${scripts.join(' + ')}, indikasi kuat serangan homograph.`]);
    if (nonAscii.length) warnings.push(['warn', `Input mengandung ${nonAscii.length} karakter non-ASCII unik.`]);
    if (u.username || u.password) warnings.push(['error', 'URL berisi kredensial (<code>user:pass@</code>). Trik ini sering dipakai untuk menyamarkan host asli.']);
    if (isIp) warnings.push(['warn', 'Host berupa alamat IP, bukan nama domain.']);
    if (host.split('.').length > 5) warnings.push(['warn', 'Banyak level subdomain, pola umum di URL phishing.']);
    if (/%25[0-9a-f]{2}/i.test(raw)) warnings.push(['warn', 'Terdeteksi double URL-encoding (<code>%25XX</code>).']);
    if (raw.length > 2000) warnings.push(['warn', `URL sangat panjang (${raw.length} karakter).`]);

    const port = u.port || (DEFAULT_PORTS[u.protocol] ? `${DEFAULT_PORTS[u.protocol]} (default)` : '–');
    const rows = [
      ['Scheme', u.protocol.replace(/:$/, '')],
      ['Hostname', host || '–'],
      ...(isPuny ? [['Hostname (Unicode)', unicodeHost]] : []),
      ['Port', port],
      ['Path', u.pathname || '/'],
      ['Query', u.search ? u.search.slice(1) : '–'],
      ['Fragment', u.hash ? u.hash.slice(1) : '–'],
      ['Username', u.username ? decodeURIComponent(u.username) : '–'],
      ['Origin', u.origin !== 'null' ? u.origin : '–'],
      ['URL ternormalisasi', u.href],
    ];

    const params = [...u.searchParams.entries()];
    const nonAsciiHtml = nonAscii.length ? `
      <div class="card">
        <h3 class="card-title">Karakter non-ASCII</h3>
        <div class="table-wrap"><table class="table">
          <thead><tr><th>Karakter</th><th>Code point</th><th>Skrip</th></tr></thead>
          <tbody>${nonAscii.slice(0, 50).map((c) => {
            const script = (SCRIPTS.find(([, re]) => re.test(c)) || ['Lainnya'])[0];
            return `<tr><td class="mono text-base">${esc(c)}</td><td class="mono">U+${c.codePointAt(0).toString(16).toUpperCase().padStart(4, '0')}</td><td>${script}</td></tr>`;
          }).join('')}</tbody>
        </table></div>
      </div>` : '';

    box.innerHTML = `
      <div class="flex flex-wrap items-center gap-2 mb-3">
        ${https ? '<span class="pill pill-ok">HTTPS</span>' : '<span class="pill pill-bad">Bukan HTTPS</span>'}
        ${isPuny ? '<span class="pill pill-warn">Punycode</span>' : '<span class="pill pill-unk">Tanpa punycode</span>'}
        ${nonAscii.length ? '<span class="pill pill-warn">Non-ASCII</span>' : '<span class="pill pill-unk">ASCII saja</span>'}
      </div>
      ${warnings.length ? `<div class="space-y-2 mb-4">${warnings.map(([t, m]) => alertBox(t, m)).join('')}</div>` : ''}
      <div class="grid lg:grid-cols-2 gap-4">
        <div class="card">
          <h3 class="card-title">Komponen</h3>
          <div class="table-wrap"><table class="table"><tbody>
            ${rows.map(([k, v]) => `<tr><th scope="row">${k}</th><td class="mono">${esc(v)}</td></tr>`).join('')}
          </tbody></table></div>
        </div>
        <div class="space-y-4">
          <div class="card">
            <h3 class="card-title">Parameter query <span class="count">${params.length}</span></h3>
            ${params.length ? `<div class="table-wrap"><table class="table">
              <thead><tr><th>Key</th><th>Value (decoded)</th></tr></thead>
              <tbody>${params.map(([k, v]) => `<tr><td class="mono">${esc(k)}</td><td class="mono">${esc(v) || '<span class="muted">(kosong)</span>'}</td></tr>`).join('')}</tbody>
            </table></div>` : '<p class="muted text-sm">Tidak ada parameter.</p>'}
          </div>
          ${nonAsciiHtml}
        </div>
      </div>`;
  }

  $('#urlInput').addEventListener('input', inspectUrl);
  $('#urlSample').addEventListener('click', () => {
    $('#urlInput').value = 'http://admin:secret@xn--80ak6aa92e.com:8443/login/../akun?next=%2Fdashboard&ref=email&token=#otp';
    inspectUrl();
  });
  $('#urlClear').addEventListener('click', () => { $('#urlInput').value = ''; inspectUrl(); $('#urlInput').focus(); });

  // 6. Subdomain Finder
  const SUBDOMAIN_WORDS = unique(`www www1 www2 mail mail2 webmail smtp pop pop3 imap mx mx1 mx2 ns ns1 ns2 ns3 dns dns1 dns2
api api2 app apps dev dev2 development staging stage stg test test2 testing qa uat sandbox demo beta alpha preview prod production
admin administrator portal login sso auth id accounts account vpn vpn2 remote gateway gw proxy cdn static assets img images media
files download downloads upload uploads docs doc wiki help support status blog shop store pay payment billing m mobile ftp sftp
git gitlab jenkins ci build jira confluence grafana kibana monitor monitoring metrics prometheus elastic db database mysql sql redis
backup intranet internal corp office exchange owa autodiscover lyncdiscover cpanel whm webdisk server server1 host web web1 web2
cloud cms crm erp hr calendar chat news forum community events careers jobs partner partners secure ssl sip voip video live stream
search analytics track ads email newsletter marketing go link s3 storage vault k8s registry docker origin edge lb old new legacy
v1 v2 my dashboard console panel manage manager crm2 helpdesk ticket tickets learn academy events2 mta relay`.split(/\s+/).filter(Boolean));

  $('#subWordCount').textContent = SUBDOMAIN_WORDS.length;

  let subAbort = null;
  let subResults = [];
  let subWildcard = [];

  function renderSubResults() {
    const tbody = $('#subResults');
    $('#subCount').textContent = subResults.length;
    $('#subCsv').disabled = $('#subJson').disabled = !subResults.length;
    if (!subResults.length) {
      tbody.innerHTML = `<tr><td colspan="3" class="empty">${subAbort ? 'Mencari…' : 'Belum ada hasil.'}</td></tr>`;
      return;
    }
    const sorted = [...subResults].sort((a, b) => a.subdomain.localeCompare(b.subdomain));
    tbody.innerHTML = sorted.map((r) => `
      <tr>
        <td class="mono">${esc(r.subdomain)}${r.wildcard ? ' <span class="badge badge-warn">wildcard?</span>' : ''}</td>
        <td class="mono">${r.ips.map(esc).join('<br>')}</td>
        <td class="mono">${r.cname.length ? r.cname.map(esc).join('<br>') : '<span class="muted">–</span>'}</td>
      </tr>`).join('');
  }

  function setSubProgress(done, total, extra = '') {
    const pct = total ? Math.round((done / total) * 100) : 0;
    $('#subProgress > span').style.width = pct + '%';
    $('#subProgress').setAttribute('aria-valuenow', String(pct));
    $('#subProgressPct').textContent = pct + '%';
    $('#subProgressText').textContent = `${done} / ${total} dicek${extra}`;
  }

  /** Scan subdomain dengan pool worker (maks 10 request paralel). */
  async function startSubdomainScan() {
    const domain = normalizeDomain($('#subDomain').value);
    const notice = $('#subNotice');
    if (!DOMAIN_RE.test(domain)) {
      notice.innerHTML = alertBox('error', 'Domain tidak valid. Contoh: <code>example.com</code>');
      return;
    }
    $('#subDomain').value = domain;

    const extra = $('#subExtra').value.split(/[\s,;]+/).map((w) => w.trim().toLowerCase())
      .filter((w) => /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/.test(w));
    const words = unique([...SUBDOMAIN_WORDS, ...extra]);
    const concurrency = Math.min(10, Math.max(1, Number($('#subConcurrency').value) || 10));

    subAbort = new AbortController();
    const { signal } = subAbort;
    subResults = [];
    subWildcard = [];
    let done = 0, errors = 0, lastError = '';
    $('#subStart').disabled = true;
    $('#subStop').disabled = false;
    notice.innerHTML = spinner('Cek wildcard DNS…');
    renderSubResults();
    setSubProgress(0, words.length);

    // Deteksi wildcard: nama acak yang tidak mungkin ada.
    try {
      const probe = `ct-${Math.random().toString(36).slice(2, 12)}.${domain}`;
      const data = await dohQuery(probe, 'A', { signal });
      subWildcard = answersOf(data, 1);
    } catch (err) {
      if (signal.aborted) { finishSub('Dihentikan.'); return; }
    }
    notice.innerHTML = subWildcard.length
      ? alertBox('warn', `Domain ini memakai <strong>wildcard DNS</strong> (nama acak resolve ke ${subWildcard.map(esc).join(', ')}). Hasil dengan IP yang sama ditandai <em>wildcard?</em>.`)
      : '';

    let next = 0;
    const worker = async () => {
      while (next < words.length && !signal.aborted) {
        const fqdn = `${words[next++]}.${domain}`;
        try {
          const data = await dohQuery(fqdn, 'A', { signal });
          const ips = answersOf(data, 1);
          if (data.Status === 0 && ips.length) {
            const wildcard = subWildcard.length > 0 && ips.every((ip) => subWildcard.includes(ip));
            subResults.push({ subdomain: fqdn, ips, cname: answersOf(data, 5), wildcard });
            renderSubResults();
          }
        } catch (err) {
          if (signal.aborted) return;
          errors++;
          lastError = friendlyError(err);
        }
        done++;
        setSubProgress(done, words.length, errors ? ` · ${errors} error` : '');
      }
    };
    await Promise.all(Array.from({ length: concurrency }, worker));

    if (signal.aborted) finishSub(`Dihentikan setelah ${done} dari ${words.length} nama.`);
    else finishSub(`Selesai: ${subResults.length} subdomain ditemukan dari ${words.length} nama.`, errors, lastError);
  }

  function finishSub(message, errors = 0, lastError = '') {
    subAbort = null;
    $('#subStart').disabled = false;
    $('#subStop').disabled = true;
    $('#subProgressText').textContent = message;
    const notice = $('#subNotice');
    if (errors) {
      notice.insertAdjacentHTML('beforeend', `<div class="mt-2">${alertBox('error', `${errors} query gagal. Error terakhir: ${esc(lastError)}. Coba kurangi jumlah paralel atau ulangi nanti.`)}</div>`);
    }
    renderSubResults();
  }

  $('#subStart').addEventListener('click', startSubdomainScan);
  $('#subDomain').addEventListener('keydown', (e) => { if (e.key === 'Enter' && !subAbort) startSubdomainScan(); });
  $('#subStop').addEventListener('click', () => { if (subAbort) subAbort.abort(); });
  $('#subCsv').addEventListener('click', () => {
    const rows = subResults.map((r) => [r.subdomain, r.ips.join(' '), r.cname.join(' '), r.wildcard ? 'yes' : 'no']);
    download(`subdomains-${stamp()}.csv`, toCSV([['subdomain', 'ips', 'cname', 'wildcard_suspect'], ...rows]), 'text/csv');
  });
  $('#subJson').addEventListener('click', () => {
    download(`subdomains-${stamp()}.json`, JSON.stringify({ wildcard: subWildcard, results: subResults }, null, 2), 'application/json');
  });

  // 7. Website Crawler: hanya halaman awal (kedalaman 1), link tidak diikuti.

  // Proxy publik gratis sering down atau kena rate limit, jadi dicoba berurutan.
  const CRAWL_PROXIES = [
    { name: 'allorigins (raw)', url: (u) => PROXY_RAW + encodeURIComponent(u), read: readProxyText },
    { name: 'allorigins (get)', url: (u) => PROXY_GET + encodeURIComponent(u), read: readAlloriginsJson },
    { name: 'codetabs', url: (u) => 'https://api.codetabs.com/v1/proxy/?quest=' + encodeURIComponent(u), read: readProxyText },
    { name: 'corsproxy.io', url: (u) => 'https://corsproxy.io/?url=' + encodeURIComponent(u), read: readProxyText },
  ];
  const MAX_HTML_CHARS = 5_000_000;

  const CRAWL_TABS = [
    ['internal', 'Internal links', 'Tidak ada link ke domain yang sama di halaman ini.'],
    ['external', 'External links', 'Halaman ini tidak menautkan domain lain.'],
    ['scripts', 'Scripts', 'Tidak ada script eksternal (src). Script inline dihitung di ringkasan.'],
    ['stylesheets', 'Stylesheets', 'Tidak ada stylesheet eksternal.'],
    ['images', 'Images', 'Tidak ada tag img dengan src.'],
    ['forms', 'Forms', 'Halaman ini tidak memiliki form.'],
    ['emails', 'Emails', 'Tidak ada alamat email di HTML maupun link mailto.'],
  ];

  let crawlData = null;
  let crawlTab = 'internal';
  let crawlAbort = null;

  const stripWww = (h) => h.replace(/^www\./, '');
  const hostOf = (u) => { try { return new URL(u).hostname; } catch { return ''; } };

  async function readProxyText(res) {
    if (!res.ok) throw new Error(`HTTP ${res.status}${res.status === 429 ? ' (rate limit)' : ''}`);
    return { html: await res.text(), httpStatus: null, contentType: res.headers.get('content-type') || '' };
  }

  // Endpoint /get membungkus HTML dalam JSON dan ikut melaporkan kode HTTP asli target.
  async function readAlloriginsJson(res) {
    if (!res.ok) throw new Error(`HTTP ${res.status}${res.status === 429 ? ' (rate limit)' : ''}`);
    const data = await res.json();
    const code = data?.status?.http_code || null;
    if (!data?.contents) throw new Error(code ? `target membalas HTTP ${code} tanpa isi` : 'target tidak merespons ke proxy');
    if (data.contents.startsWith('data:')) throw new Error('respons target bukan teks');
    return { html: data.contents, httpStatus: code, contentType: data.status?.content_type || '' };
  }

  // Proxy yang gagal sering membalas 200 berisi JSON atau teks error, bukan HTML.
  const looksLikeHtml = (s) => /<(?:!doctype|html|head|body|title|meta|a|div|p|script)\b/i.test(s.slice(0, 50000));

  /** Coba setiap proxy sampai satu berhasil; tiap percobaan dibatasi 8 detik termasuk membaca body. */
  async function fetchViaProxies(target, signal, onUpdate) {
    const attempts = [];
    for (const proxy of CRAWL_PROXIES) {
      const attempt = { name: proxy.name, state: 'pending', detail: '' };
      attempts.push(attempt);
      onUpdate(attempts);
      const ctrl = new AbortController();
      let timedOut = false;
      const stop = () => ctrl.abort();
      const timer = setTimeout(() => { timedOut = true; ctrl.abort(); }, REQUEST_TIMEOUT);
      signal.addEventListener('abort', stop, { once: true });
      const t0 = performance.now();
      try {
        const res = await fetchWithTimeout(proxy.url(target), { signal: ctrl.signal, cache: 'no-store' });
        const out = await proxy.read(res);
        if (!out.html.trim()) throw new Error('respons kosong');
        if (!looksLikeHtml(out.html)) throw new Error('respons bukan HTML (kemungkinan pesan error proxy)');
        attempt.state = 'ok';
        attempt.detail = formatMs(performance.now() - t0);
        onUpdate(attempts);
        return { ...out, proxy: proxy.name, elapsedMs: Math.round(performance.now() - t0), attempts };
      } catch (err) {
        if (signal.aborted) throw new DOMException('Dibatalkan', 'AbortError');
        attempt.state = 'fail';
        attempt.detail = timedOut ? 'timeout 8 detik' : friendlyError(err);
        onUpdate(attempts);
      } finally {
        clearTimeout(timer);
        signal.removeEventListener('abort', stop);
      }
    }
    const err = new Error('Semua proxy gagal mengambil halaman');
    err.attempts = attempts;
    throw err;
  }

  /** Parse HTML tanpa mengeksekusinya (DOMParser tidak menjalankan script atau memuat gambar). */
  function parsePage(html, pageUrl) {
    const doc = new DOMParser().parseFromString(html, 'text/html');
    const baseEl = doc.querySelector('base[href]');
    let base = pageUrl;
    if (baseEl) { try { base = new URL(baseEl.getAttribute('href'), pageUrl).href; } catch { /* base tidak valid, pakai URL halaman */ } }
    const resolve = (v) => { try { return new URL(String(v).trim(), base).href; } catch { return null; } };
    const pageHost = stripWww(new URL(pageUrl).hostname);
    const isInternal = (u) => stripWww(hostOf(u)) === pageHost;

    const internal = new Map(), external = new Map(), emails = new Set();
    let blankNoOpener = 0;
    for (const a of doc.querySelectorAll('a[href]')) {
      const href = a.getAttribute('href').trim();
      if (/^mailto:/i.test(href)) {
        let addr = href.slice(7).split('?')[0];
        try { addr = decodeURIComponent(addr); } catch { /* biarkan apa adanya */ }
        addr.split(',').map((e) => e.trim().toLowerCase()).filter(Boolean).forEach((e) => emails.add(e));
        continue;
      }
      if (!href || href.startsWith('#') || /^(javascript|tel|data|sms):/i.test(href)) continue;
      const abs = resolve(href);
      if (!abs || !/^https?:/i.test(abs)) continue;
      const rel = (a.getAttribute('rel') || '').toLowerCase();
      if (a.getAttribute('target') === '_blank' && !/noopener|noreferrer/.test(rel)) blankNoOpener++;
      const text = (a.textContent || a.getAttribute('title') || a.getAttribute('aria-label') || '').replace(/\s+/g, ' ').trim().slice(0, 120);
      const bucket = isInternal(abs) ? internal : external;
      if (!bucket.has(abs)) bucket.set(abs, { url: abs, text });
    }

    const urlsOf = (nodes, attr) => unique(nodes.map((n) => n.getAttribute(attr)).filter(Boolean).map(resolve).filter((u) => u && /^https?:/i.test(u)));
    const scripts = urlsOf([...doc.querySelectorAll('script[src]')], 'src').map((url) => ({ url }));
    const stylesheets = urlsOf([...doc.querySelectorAll('link[href]')].filter((l) => /\bstylesheet\b/i.test(l.getAttribute('rel') || '')), 'href').map((url) => ({ url }));
    const imgMap = new Map();
    for (const img of doc.querySelectorAll('img')) {
      const src = img.getAttribute('src') || img.getAttribute('data-src');
      if (!src || /^data:/i.test(src)) continue;
      const abs = resolve(src);
      if (abs && /^https?:/i.test(abs) && !imgMap.has(abs)) imgMap.set(abs, { url: abs, text: (img.getAttribute('alt') || '').trim().slice(0, 120) });
    }

    const forms = [...doc.querySelectorAll('form')].map((f, i) => {
      const action = resolve(f.getAttribute('action') || pageUrl) || pageUrl;
      const fields = [...f.querySelectorAll('input, select, textarea')]
        .filter((el) => (el.getAttribute('type') || '').toLowerCase() !== 'submit')
        .map((el) => ({ name: el.getAttribute('name') || '', type: (el.getAttribute('type') || el.tagName).toLowerCase() }));
      return {
        index: i + 1,
        action,
        method: (f.getAttribute('method') || 'GET').toUpperCase(),
        fields,
        hasPassword: fields.some((x) => x.type === 'password'),
        externalAction: !isInternal(action),
        insecure: /^http:/i.test(action),
      };
    });

    // Filter TLD ekstensi file agar "logo@2x.png" tidak terbaca sebagai email.
    const bodyText = (doc.body?.textContent || '').replace(/\s+/g, ' ').trim();
    for (const m of (bodyText + ' ' + html).matchAll(/\b[a-z0-9._%+-]+@(?:[a-z0-9-]+\.)+[a-z]{2,24}\b/gi)) {
      if (!FILE_EXT.has(m[0].split('.').pop().toLowerCase())) emails.add(m[0].toLowerCase());
    }

    const meta = (sel) => (doc.querySelector(sel)?.getAttribute('content') || '').trim();
    return {
      url: pageUrl,
      host: pageHost,
      title: (doc.querySelector('title')?.textContent || '').replace(/\s+/g, ' ').trim(),
      description: meta('meta[name="description" i]') || meta('meta[property="og:description" i]'),
      lang: doc.documentElement.getAttribute('lang') || '',
      generator: meta('meta[name="generator" i]'),
      robots: meta('meta[name="robots" i]'),
      canonical: resolve(doc.querySelector('link[rel="canonical" i]')?.getAttribute('href') || '') || '',
      inlineScripts: doc.querySelectorAll('script:not([src])').length,
      textLength: bodyText.length,
      blankNoOpener,
      internal: [...internal.values()],
      external: [...external.values()],
      scripts,
      stylesheets,
      images: [...imgMap.values()],
      forms,
      emails: [...emails].sort().map((email) => ({ email })),
    };
  }

  /** Observasi keamanan yang bisa dibuktikan langsung dari HTML. */
  function crawlNotes(d) {
    const notes = [];
    const pageHttps = d.url.startsWith('https:');
    if (!pageHttps) notes.push(['warn', 'Halaman disajikan lewat HTTP tanpa enkripsi.']);
    const mixed = [...d.scripts, ...d.stylesheets, ...d.images].filter((x) => x.url.startsWith('http:'));
    if (pageHttps && mixed.length) notes.push(['warn', `${mixed.length} aset dimuat lewat HTTP di halaman HTTPS (mixed content).`]);
    for (const f of d.forms) {
      if (f.hasPassword && f.insecure) notes.push(['warn', `Form #${f.index} mengirim password ke URL HTTP tanpa enkripsi.`]);
      else if (f.hasPassword && f.externalAction) notes.push(['warn', `Form #${f.index} mengirim password ke domain lain: ${esc(hostOf(f.action))}.`]);
      else if (f.insecure && pageHttps) notes.push(['warn', `Form #${f.index} mengirim data ke URL HTTP.`]);
    }
    const thirdParty = unique(d.scripts.map((s) => stripWww(hostOf(s.url))).filter((h) => h && h !== d.host));
    if (thirdParty.length) {
      const shown = thirdParty.slice(0, 5).map((h) => `<span class="mono">${esc(h)}</span>`).join(', ');
      notes.push(['info', `Script pihak ketiga dari ${thirdParty.length} domain: ${shown}${thirdParty.length > 5 ? ', dan lainnya' : ''}.`]);
    }
    if (d.blankNoOpener) notes.push(['info', `${d.blankNoOpener} link <code>target="_blank"</code> tanpa <code>rel="noopener"</code> (risiko tabnabbing di browser lama).`]);
    if (d.textLength < 200 && (d.scripts.length || d.inlineScripts)) {
      notes.push(['info', 'Teks halaman sangat sedikit. Konten kemungkinan dirender JavaScript dan tidak terbaca crawler ini, yang hanya membaca HTML awal.']);
    }
    return notes;
  }

  function renderAttempts(attempts) {
    const list = $('#crawlAttempts');
    list.hidden = false;
    const label = { pending: 'Mencoba', ok: 'Berhasil', fail: 'Gagal' };
    list.innerHTML = attempts.map((a) => `
      <li class="attempt attempt-${a.state}">
        <span class="attempt-state">${a.state === 'pending' ? '<span class="spinner" aria-hidden="true"></span> ' : ''}${label[a.state]}</span>
        <span class="mono">${esc(a.name)}</span>
        ${a.detail ? `<span class="muted">${esc(a.detail)}</span>` : ''}
      </li>`).join('');
  }

  // Path relatif lebih mudah dipindai daripada URL penuh yang host-nya berulang.
  function pathOf(u) {
    try { const x = new URL(u); return (x.pathname + x.search + x.hash) || '/'; } catch { return u; }
  }

  function urlRow(item, { showHost }) {
    const label = showHost ? item.url : pathOf(item.url);
    return `
      <div class="result-row">
        <span class="value">
          <a class="mono" href="${esc(item.url)}" target="_blank" rel="noopener noreferrer nofollow" title="${esc(item.url)}">${esc(label)}</a>
          ${item.text ? `<span class="row-text">${esc(item.text)}</span>` : ''}
        </span>
        <button type="button" class="copy-btn" data-copy="${esc(item.url)}" aria-label="Copy ${esc(item.url)}">Copy</button>
      </div>`;
  }

  function filteredItems() {
    const q = $('#crawlFilter').value.trim().toLowerCase();
    return crawlData[crawlTab].filter((it) => !q || JSON.stringify(it).toLowerCase().includes(q));
  }

  function renderCrawlList() {
    if (!crawlData) return;
    $$('#crawlTabs .count-tab').forEach((b) => {
      const active = b.dataset.key === crawlTab;
      b.setAttribute('aria-selected', String(active));
      b.tabIndex = active ? 0 : -1;
    });
    const items = filteredItems();
    const list = $('#crawlList');
    if (!items.length) {
      const emptyMsg = CRAWL_TABS.find(([k]) => k === crawlTab)[2];
      list.innerHTML = `<div class="empty">${$('#crawlFilter').value.trim() ? 'Tidak ada item yang cocok dengan filter.' : esc(emptyMsg)}</div>`;
      return;
    }

    if (crawlTab === 'forms') {
      list.innerHTML = items.map((f) => `
        <div class="result-group">
          <div class="result-group-head">
            <span>Form #${f.index} <span class="badge badge-muted mono">${esc(f.method)}</span></span>
            <span class="flex flex-wrap gap-1">
              ${f.hasPassword ? '<span class="badge badge-warn">field password</span>' : ''}
              ${f.externalAction ? '<span class="badge badge-warn">action ke domain lain</span>' : ''}
              ${f.insecure ? '<span class="badge badge-warn">action HTTP</span>' : ''}
            </span>
          </div>
          <div class="result-row"><span class="value"><span class="muted text-xs">Action</span><br><a class="mono" href="${esc(f.action)}" target="_blank" rel="noopener noreferrer nofollow">${esc(f.action)}</a></span></div>
          <div class="result-row"><span class="value">
            ${f.fields.length ? f.fields.map((x) => `<span class="field-chip mono">${esc(x.name || '(tanpa nama)')} <span class="muted">${esc(x.type)}</span></span>`).join('') : '<span class="muted">Tidak ada field input.</span>'}
          </span></div>
        </div>`).join('');
      return;
    }

    if (crawlTab === 'emails') {
      list.innerHTML = `<div class="result-group">${items.map((e) => `
        <div class="result-row"><span class="value mono">${esc(e.email)}</span><button type="button" class="copy-btn" data-copy="${esc(e.email)}">Copy</button></div>`).join('')}</div>`;
      return;
    }

    if (crawlTab === 'internal') {
      list.innerHTML = `<div class="result-group">${items.map((it) => urlRow(it, { showHost: false })).join('')}</div>`;
      return;
    }

    // Aset dan link eksternal dikelompokkan per host: inventaris pihak ketiga langsung terlihat.
    const groups = new Map();
    for (const it of items) {
      const h = hostOf(it.url);
      if (!groups.has(h)) groups.set(h, []);
      groups.get(h).push(it);
    }
    list.innerHTML = [...groups.entries()].sort((a, b) => b[1].length - a[1].length).map(([h, rows]) => `
      <div class="result-group">
        <div class="result-group-head">
          <span class="mono">${esc(h)}${stripWww(h) === crawlData.host ? ' <span class="muted font-normal">(domain ini)</span>' : ''}</span>
          <span class="count">${rows.length}</span>
        </div>
        ${rows.map((it) => urlRow(it, { showHost: false })).join('')}
      </div>`).join('');
  }

  function renderCrawlReport(d) {
    const fetched = new Date(d.fetchedAt).toLocaleString('id-ID', { dateStyle: 'medium', timeStyle: 'short' });
    $('#crawlMeta').textContent = `Diambil ${fetched} lewat ${d.proxy}`;
    $('#crawlTitle').textContent = d.title || '(halaman tanpa title)';
    $('#crawlTitle').classList.toggle('muted', !d.title);
    const link = $('#crawlLink');
    link.href = d.url;
    link.textContent = d.url;
    $('#crawlDesc').textContent = d.description || 'Tidak ada meta description.';
    $('#crawlDesc').classList.toggle('muted', !d.description);

    const facts = [
      ['Status HTTP', d.httpStatus ? String(d.httpStatus) : 'Tidak dilaporkan proxy'],
      ['Ukuran HTML', `${(d.bytes / 1024).toFixed(1)} KB${d.truncated ? ' (dipotong)' : ''}`],
      ['Waktu ambil', formatMs(d.elapsedMs)],
      ['Script inline', String(d.inlineScripts)],
      ...(d.lang ? [['Bahasa', d.lang]] : []),
      ...(d.generator ? [['Generator', d.generator]] : []),
      ...(d.robots ? [['Robots', d.robots]] : []),
      ...(d.canonical && d.canonical !== d.url ? [['Canonical', d.canonical]] : []),
    ];
    $('#crawlFacts').innerHTML = facts.map(([k, v]) => `<div${k === 'Canonical' ? ' class="fact-wide"' : ''}><dt>${esc(k)}</dt><dd${k === 'Canonical' ? ' class="mono"' : ''}>${esc(v)}</dd></div>`).join('');

    const notes = crawlNotes(d);
    $('#crawlNotes').innerHTML = notes.length
      ? `<h4 class="notes-title">Catatan keamanan</h4><ul class="notes">${notes.map(([tone, html]) => `<li class="note note-${tone}"><span class="note-label">${tone === 'warn' ? 'Perhatian' : 'Info'}</span><span>${html}</span></li>`).join('')}</ul>`
      : '<p class="muted text-sm">Tidak ada catatan keamanan dari HTML halaman ini.</p>';

    $('#crawlTabs').innerHTML = CRAWL_TABS.map(([key, label]) => `
      <button type="button" class="count-tab" role="tab" id="ctab-${key}" data-key="${key}" aria-controls="crawlTabPanel" aria-selected="false" tabindex="-1">
        <span class="n${d[key].length ? '' : ' zero'}">${d[key].length}</span><span class="l">${label}</span>
      </button>`).join('');
    $('#crawlFilter').value = '';
    $('#crawlEmpty').hidden = true;
    $('#crawlReport').hidden = false;
    renderCrawlList();
  }

  function setCrawlBusy(busy) {
    $('#crawlStart').disabled = busy;
    $('#crawlCancel').hidden = !busy;
    $('#crawlUrl').readOnly = busy;
  }

  async function startCrawl() {
    if (crawlAbort) return;
    const status = $('#crawlStatus');
    let target;
    try { target = toHttpUrl($('#crawlUrl').value); } catch (err) {
      status.innerHTML = alertBox('error', esc(err.message === 'Invalid URL' ? 'URL tidak valid. Contoh: https://example.com' : err.message));
      $('#crawlUrl').focus();
      return;
    }
    $('#crawlUrl').value = target.href;
    status.innerHTML = '';
    $('#crawlReport').hidden = true;
    $('#crawlEmpty').hidden = true;
    crawlAbort = new AbortController();
    setCrawlBusy(true);
    try {
      const res = await fetchViaProxies(target.href, crawlAbort.signal, renderAttempts);
      const truncated = res.html.length > MAX_HTML_CHARS;
      const html = truncated ? res.html.slice(0, MAX_HTML_CHARS) : res.html;
      crawlData = {
        ...parsePage(html, target.href),
        fetchedAt: new Date().toISOString(),
        proxy: res.proxy,
        httpStatus: res.httpStatus,
        bytes: utf8.encode(html).length,
        truncated,
        elapsedMs: res.elapsedMs,
      };
      crawlTab = 'internal';
      renderCrawlReport(crawlData);
      $('#crawlAttempts').hidden = true;
    } catch (err) {
      if (err.name === 'AbortError') {
        status.innerHTML = alertBox('info', 'Crawl dibatalkan.');
      } else {
        status.innerHTML = alertBox('error', `<strong>Halaman tidak bisa diambil.</strong> Semua proxy gagal (rincian di atas). Penyebab umum: proxy publik sedang down atau kena rate limit, situs memblokir proxy, atau URL salah ketik. Coba lagi beberapa menit lagi, atau cek URL dengan tool <em>Is It Down</em>.`);
      }
    } finally {
      crawlAbort = null;
      setCrawlBusy(false);
    }
  }

  $('#crawlForm').addEventListener('submit', (e) => { e.preventDefault(); startCrawl(); });
  $('#crawlCancel').addEventListener('click', () => { if (crawlAbort) crawlAbort.abort(); });
  $('#crawlTabs').addEventListener('click', (e) => {
    const btn = e.target.closest('.count-tab');
    if (btn) { crawlTab = btn.dataset.key; renderCrawlList(); }
  });
  $('#crawlTabs').addEventListener('keydown', (e) => {
    const keys = CRAWL_TABS.map(([k]) => k);
    let i = keys.indexOf(crawlTab);
    if (e.key === 'ArrowRight') i = (i + 1) % keys.length;
    else if (e.key === 'ArrowLeft') i = (i - 1 + keys.length) % keys.length;
    else if (e.key === 'Home') i = 0;
    else if (e.key === 'End') i = keys.length - 1;
    else return;
    e.preventDefault();
    crawlTab = keys[i];
    renderCrawlList();
    $(`#ctab-${crawlTab}`).focus();
  });
  $('#crawlFilter').addEventListener('input', renderCrawlList);
  $('#crawlCopy').addEventListener('click', () => {
    if (!crawlData) return;
    const items = filteredItems();
    const lines = crawlTab === 'emails' ? items.map((e) => e.email)
      : crawlTab === 'forms' ? items.map((f) => `${f.method} ${f.action}`)
        : items.map((it) => it.url);
    copyText(lines.join('\n'));
  });
  $('#crawlCsv').addEventListener('click', () => {
    if (!crawlData) return;
    const rows = [['type', 'url', 'text']];
    for (const [key] of CRAWL_TABS) {
      for (const it of crawlData[key]) {
        if (key === 'forms') rows.push(['form', it.action, `${it.method} ${it.fields.map((f) => f.name || f.type).join(' ')}`]);
        else if (key === 'emails') rows.push(['email', it.email, '']);
        else rows.push([key, it.url, it.text || '']);
      }
    }
    download(`crawl-${stamp()}.csv`, toCSV(rows), 'text/csv');
  });
  $('#crawlExport').addEventListener('click', () => {
    if (crawlData) download(`crawl-${stamp()}.json`, JSON.stringify(crawlData, null, 2), 'application/json');
  });

  // 8. Is It Down
  const HISTORY_KEY = 'isdown-history';
  let lastTarget = '';
  let downBusy = false;

  /** Metode 1: resolusi DNS via Cloudflare DoH (A lalu AAAA). */
  async function checkDNS(host) {
    if (IPV4_RE.test(host) || host.startsWith('[')) return { ok: true, skipped: true, detail: 'Host berupa IP, DNS dilewati' };
    const t0 = performance.now();
    try {
      let data = await dohQuery(host, 'A');
      let ips = answersOf(data, 1);
      if (data.Status === 0 && !ips.length) {
        const v6 = await dohQuery(host, 'AAAA');
        ips = answersOf(v6, 28);
      }
      const ms = performance.now() - t0;
      if (data.Status === 3) return { ok: false, definitive: true, ms, detail: 'NXDOMAIN, domain tidak ada' };
      if (data.Status !== 0) return { ok: false, ms, detail: `DNS ${DNS_RCODE[data.Status] || 'rcode ' + data.Status}` };
      if (!ips.length) return { ok: false, definitive: true, ms, detail: 'Tidak ada record A/AAAA' };
      return { ok: true, ms, detail: ips.slice(0, 4).join(', ') + (ips.length > 4 ? ` +${ips.length - 4}` : '') };
    } catch (err) {
      return { ok: false, ms: performance.now() - t0, detail: friendlyError(err) };
    }
  }

  /** Metode 2: HTTP HEAD lewat proxy allorigins; fallback /get untuk membaca kode status asli. */
  async function checkHTTP(url) {
    const t0 = performance.now();
    try {
      const res = await fetchWithTimeout(PROXY_RAW + encodeURIComponent(url), { method: 'HEAD', cache: 'no-store' });
      if (res.ok) return { ok: true, ms: performance.now() - t0, code: res.status, detail: `HTTP ${res.status} (HEAD)` };
    } catch { /* lanjut ke fallback */ }
    const t1 = performance.now();
    try {
      const res = await fetchWithTimeout(PROXY_GET + encodeURIComponent(url), { cache: 'no-store' });
      if (!res.ok) return { ok: false, ms: performance.now() - t1, detail: `Proxy HTTP ${res.status}` };
      const data = await res.json();
      const code = data?.status?.http_code;
      const ms = data?.status?.response_time ?? performance.now() - t1;
      if (!code) return { ok: false, ms, detail: 'Target tidak merespons ke proxy' };
      return { ok: code < 500, ms, code, detail: `HTTP ${code}${code >= 500 ? ' (server error)' : ''}` };
    } catch (err) {
      return { ok: false, ms: performance.now() - t1, detail: friendlyError(err) };
    }
  }

  /** Metode 3: jangkauan langsung dari browser (respons opaque = host merespons). */
  async function checkDirect(url) {
    const t0 = performance.now();
    if (location.protocol === 'https:' && /^http:/i.test(url)) {
      return { ok: false, ms: null, detail: 'Dilewati: mixed content (halaman HTTPS ke target HTTP)', skipped: true };
    }
    try {
      await fetchWithTimeout(url, { mode: 'no-cors', cache: 'no-store', timeout: 5000 });
      return { ok: true, ms: performance.now() - t0, detail: 'Terjangkau (respons opaque)' };
    } catch (err) {
      return { ok: false, ms: performance.now() - t0, detail: friendlyError(err) };
    }
  }

  /** Gabungkan hasil 3 metode menjadi satu status. */
  function verdict(dns, http, direct) {
    if (!dns.ok && dns.definitive) return ['Down', 'bad']; // NXDOMAIN / tanpa record: tidak mungkin online
    if (http.ok || direct.ok) return ['Online', 'ok'];
    if (http.code >= 500) return ['Down', 'bad'];
    if (dns.ok && !dns.skipped) return ['DNS-only', 'warn'];
    return ['Unknown', 'unk'];
  }

  function renderHistory() {
    const list = store.get(HISTORY_KEY, []);
    const box = $('#downHistory');
    if (!list.length) { box.innerHTML = '<p class="muted text-sm">Belum ada riwayat.</p>'; return; }
    box.innerHTML = `<div class="table-wrap"><table class="table">
      <thead><tr><th>Target</th><th>Status</th><th>Waktu respons</th><th>Dicek</th><th><span class="sr-only">Aksi</span></th></tr></thead>
      <tbody>${list.map((h) => `
        <tr>
          <td class="mono">${esc(h.target)}</td>
          <td><span class="pill pill-${esc(h.tone)}">${esc(h.status)}</span></td>
          <td class="mono">${formatMs(h.ms)}</td>
          <td class="text-xs muted">${esc(new Date(h.time).toLocaleString('id-ID'))}</td>
          <td><button type="button" class="copy-btn" data-recheck="${esc(h.target)}">Re-check</button></td>
        </tr>`).join('')}</tbody>
    </table></div>`;
  }

  async function runDownCheck(rawInput) {
    if (downBusy) return;
    const box = $('#downResult');
    let target;
    try { target = toHttpUrl(rawInput); } catch (err) {
      box.innerHTML = alertBox('error', esc(err.message === 'Invalid URL' ? 'Domain/URL tidak valid' : err.message));
      return;
    }
    const host = target.hostname;
    const url = target.href;
    lastTarget = rawInput.trim();
    downBusy = true;
    $('#downCheck').disabled = $('#downRecheck').disabled = true;

    const row = (label, html) => `<tr><th scope="row">${label}</th><td>${html}</td></tr>`;
    box.innerHTML = `<div class="card">${spinner(`Mengecek ${host}…`)}
      <div class="table-wrap mt-3"><table class="table"><tbody>
        ${row('1. DNS (Cloudflare DoH)', spinner('menunggu'))}
        ${row('2. HTTP HEAD (proxy)', spinner('menunggu'))}
        ${row('3. Koneksi langsung', spinner('menunggu'))}
      </tbody></table></div></div>`;

    const [dns, http, direct] = await Promise.all([checkDNS(host), checkHTTP(url), checkDirect(url)]);
    const [status, tone] = verdict(dns, http, direct);
    const responseMs = status !== 'Online' ? null : http.ok ? http.ms : direct.ms;
    const cell = (r) => `<span class="pill pill-${r.skipped ? 'unk' : r.ok ? 'ok' : 'bad'}">${r.skipped ? 'Dilewati' : r.ok ? 'OK' : 'Gagal'}</span>
      <span class="text-sm ml-1">${esc(r.detail)}</span>${r.ms != null ? ` <span class="muted mono text-xs">· ${formatMs(r.ms)}</span>` : ''}`;

    const explain = {
      Online: 'Situs merespons. Jika Anda tidak bisa membukanya, masalah kemungkinan di jaringan atau perangkat Anda.',
      Down: 'Situs tampaknya tidak bisa diakses dari mana pun.',
      'DNS-only': 'Domain resolve, tetapi tidak ada respons HTTP. Server mungkin mati, memblokir, atau port ditutup.',
      Unknown: 'Hasil tidak meyakinkan: semua cek gagal atau timeout. Periksa koneksi Anda atau coba lagi.',
    }[status];

    box.innerHTML = `<div class="card">
      <div class="flex flex-wrap items-center gap-3">
        <span class="pill pill-${tone} text-base">${status}</span>
        <span class="mono font-semibold">${esc(host)}</span>
        <span class="muted text-sm">Waktu respons: <span class="mono">${formatMs(responseMs)}</span></span>
      </div>
      <p class="muted text-sm mt-2">${explain}</p>
      <div class="table-wrap mt-3"><table class="table"><tbody>
        ${row('1. DNS (Cloudflare DoH)', cell(dns))}
        ${row('2. HTTP HEAD (proxy)', cell(http))}
        ${row('3. Koneksi langsung', cell(direct))}
      </tbody></table></div>
    </div>`;

    const history = store.get(HISTORY_KEY, []).filter((h) => h.target !== lastTarget);
    history.unshift({ target: lastTarget, status, tone, ms: responseMs == null ? null : Math.round(responseMs), time: Date.now() });
    store.set(HISTORY_KEY, history.slice(0, 10));
    renderHistory();

    downBusy = false;
    $('#downCheck').disabled = $('#downRecheck').disabled = false;
  }

  $('#downCheck').addEventListener('click', () => runDownCheck($('#downInput').value));
  $('#downInput').addEventListener('keydown', (e) => { if (e.key === 'Enter') runDownCheck($('#downInput').value); });
  $('#downRecheck').addEventListener('click', () => { if (lastTarget) runDownCheck(lastTarget); });
  $('#downHistory').addEventListener('click', (e) => {
    const btn = e.target.closest('[data-recheck]');
    if (btn) { $('#downInput').value = btn.dataset.recheck; runDownCheck(btn.dataset.recheck); }
  });
  $('#downClearHistory').addEventListener('click', () => { store.remove(HISTORY_KEY); renderHistory(); });
  renderHistory();

  // 9. Network Check
  const LATENCY_TARGETS = [
    ['Cloudflare (1.1.1.1)', 'https://1.1.1.1/cdn-cgi/trace'],
    ['Google DNS (dns.google)', 'https://dns.google/resolve?name=example.com&type=A'],
    ['GitHub (github.com)', 'https://github.com/robots.txt'],
  ];
  const LOADING = '__loading__';
  const net = { public: {}, latency: {} };
  let netBusy = false;

  function localNetInfo() {
    const c = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
    const na = 'Tidak didukung browser ini';
    let tz = '–';
    try { tz = Intl.DateTimeFormat().resolvedOptions().timeZone; } catch { /* abaikan */ }
    const offset = -new Date().getTimezoneOffset();
    const offsetStr = `UTC${offset >= 0 ? '+' : '-'}${String(Math.floor(Math.abs(offset) / 60)).padStart(2, '0')}:${String(Math.abs(offset) % 60).padStart(2, '0')}`;
    return {
      connection: [
        ['Status', navigator.onLine ? 'Online' : 'Offline'],
        ['Connection type', c?.type || (c ? 'Tidak dilaporkan' : na)],
        ['Effective type', c?.effectiveType || na],
        ['Downlink', c?.downlink != null ? `${c.downlink} Mbps (estimasi)` : na],
        ['RTT', c?.rtt != null ? `${c.rtt} ms (estimasi)` : na],
        ['Save-Data', c ? (c.saveData ? 'Aktif' : 'Nonaktif') : na],
      ],
      device: [
        ['User agent', navigator.userAgent],
        ['Platform', navigator.userAgentData?.platform || navigator.platform || '–'],
        ['Bahasa', (navigator.languages && navigator.languages.length ? navigator.languages : [navigator.language]).join(', ')],
        ['Timezone', `${tz} (${offsetStr})`],
        ['Layar', `${screen.width}×${screen.height} @${window.devicePixelRatio || 1}x`],
        ['CPU threads', navigator.hardwareConcurrency ? String(navigator.hardwareConcurrency) : '–'],
      ],
    };
  }

  function netRows() {
    const local = localNetInfo();
    const p = net.public;
    const show = (v) => (v === LOADING ? LOADING : v || '–');
    const publicRows = [
      ['IP publik (ipify)', show(p.ip)],
      ['IP (ipapi)', show(p.ipapiIp)],
      ['Lokasi', show(p.location)],
      ['ISP / Org', show(p.org)],
      ['ASN', show(p.asn)],
      ['Timezone (berdasarkan IP)', show(p.tz)],
    ];
    const latencyRows = LATENCY_TARGETS.map(([name]) => [name, show(net.latency[name])]);
    return [
      ['Koneksi', local.connection],
      ['Jaringan publik (pihak ketiga)', publicRows],
      ['Latency (3 sampel, fetch + performance.now)', latencyRows],
      ['Perangkat & browser', local.device],
    ];
  }

  function renderNet() {
    const online = navigator.onLine;
    const pill = $('#netOnline');
    pill.className = `pill ${online ? 'pill-ok' : 'pill-bad'}`;
    pill.textContent = online ? 'Online' : 'Offline';
    const hasRun = Object.keys(net.public).length > 0;
    $('#netTable').innerHTML = netRows().map(([section, rows]) => `
      <tr class="section-row"><th colspan="2">${esc(section)}</th></tr>
      ${rows.map(([k, v]) => `<tr><th scope="row">${esc(k)}</th><td class="${k === 'User agent' ? 'text-xs' : ''} mono">${
        v === LOADING ? spinner('Memuat…')
          : (!hasRun && v === '–' && section !== 'Koneksi' && section !== 'Perangkat & browser')
            ? '<span class="muted">Klik “Cek IP &amp; latency”</span>'
            : esc(v)}</td></tr>`).join('')}`).join('');
  }

  async function measureLatency(url, samples = 3) {
    const times = [];
    let lastErr = null;
    for (let i = 0; i < samples; i++) {
      const t0 = performance.now();
      try {
        await fetchWithTimeout(url, { mode: 'no-cors', cache: 'no-store' });
        times.push(performance.now() - t0);
      } catch (err) { lastErr = err; }
    }
    if (!times.length) return `Gagal: ${friendlyError(lastErr)}`;
    const min = Math.min(...times);
    const avg = times.reduce((a, b) => a + b, 0) / times.length;
    return `min ${Math.round(min)} ms · rata-rata ${Math.round(avg)} ms (${times.length}/${samples} sukses)`;
  }

  async function runNetworkCheck() {
    if (netBusy) return;
    netBusy = true;
    $('#netRun').disabled = true;
    net.public = { ip: LOADING, ipapiIp: LOADING, location: LOADING, org: LOADING, asn: LOADING, tz: LOADING };
    net.latency = Object.fromEntries(LATENCY_TARGETS.map(([n]) => [n, LOADING]));
    renderNet();

    const ipify = (async () => {
      try {
        const res = await fetchWithTimeout('https://api.ipify.org?format=json', { cache: 'no-store' });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        net.public.ip = (await res.json()).ip || '–';
      } catch (err) { net.public.ip = `Gagal: ${friendlyError(err)}`; }
      renderNet();
    })();

    const ipapi = (async () => {
      try {
        const res = await fetchWithTimeout('https://ipapi.co/json/', { cache: 'no-store' });
        if (res.status === 429) throw new Error('Rate limit ipapi.co, coba lagi nanti');
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const d = await res.json();
        if (d.error) throw new Error(d.reason || 'ipapi.co mengembalikan error');
        Object.assign(net.public, {
          ipapiIp: d.ip || '–',
          location: [d.city, d.region, d.country_name].filter(Boolean).join(', ') || '–',
          org: d.org || '–',
          asn: d.asn || '–',
          tz: d.timezone ? `${d.timezone}${d.utc_offset ? ` (${d.utc_offset})` : ''}` : '–',
        });
      } catch (err) {
        const msg = `Gagal: ${friendlyError(err)}`;
        Object.assign(net.public, { ipapiIp: msg, location: msg, org: msg, asn: msg, tz: msg });
      }
      renderNet();
    })();

    const latency = (async () => {
      for (const [name, url] of LATENCY_TARGETS) {
        net.latency[name] = await measureLatency(url);
        renderNet();
      }
    })();

    await Promise.all([ipify, ipapi, latency]);
    netBusy = false;
    $('#netRun').disabled = false;
  }

  $('#netRun').addEventListener('click', runNetworkCheck);
  $('#netCopy').addEventListener('click', () => {
    const lines = [];
    for (const [section, rows] of netRows()) {
      lines.push(`## ${section}`);
      for (const [k, v] of rows) lines.push(`${k}: ${v === LOADING ? 'memuat…' : v}`);
      lines.push('');
    }
    copyText(lines.join('\n').trim());
  });
  window.addEventListener('online', renderNet);
  window.addEventListener('offline', renderNet);
  const conn = navigator.connection;
  if (conn && conn.addEventListener) conn.addEventListener('change', renderNet);
  renderNet();

  // Mulai: buka tab terakhir yang dipakai
  activateTab(store.get('tab', 'ioc'));
})();
