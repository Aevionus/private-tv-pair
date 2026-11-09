// A8 step 4: approving a TV from a phone. A static page: everything secret happens here, in the
// browser, with WebCrypto. The TV's pairing ID and public key arrive in the address's # part, which
// browsers never send to a server. The sync key is unlocked with the passphrase and sealed to the
// TV's key before it leaves the phone, exactly as the Windows app does (electron/sync-core.js).
'use strict';
const PairPage = (() => {
  const LABEL = 'private-tv pairing v1';
  const CHECK_LETTERS = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
  const CHECK_LABEL = 'private-tv sync check v1';
  const subtle = globalThis.crypto.subtle;
  const utf8 = text => new TextEncoder().encode(text);
  const b64 = bytes => { let s = ''; for (const b of new Uint8Array(bytes)) s += String.fromCharCode(b); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); };
  const unb64 = text => {
    if (typeof text !== 'string' || !/^[A-Za-z0-9_-]*$/.test(text)) throw new Error('invalid');
    const s = atob(text.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((text.length + 3) % 4));
    return Uint8Array.from(s, c => c.charCodeAt(0));
  };
  const hex = bytes => [...new Uint8Array(bytes)].map(b => b.toString(16).padStart(2, '0')).join('');
  const unhex = text => Uint8Array.from(text.match(/../g) || [], h => parseInt(h, 16));
  const concat = (...parts) => { const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0)); let at = 0; for (const p of parts) { out.set(p, at); at += p.length; } return out; };
  const MESSAGES = {
    offline: 'Can\'t reach the sync service. Check this phone\'s connection and try again.',
    unavailable: 'The sync service isn\'t answering right now. Try again in a minute.',
    login: 'That email and password weren\'t accepted.',
    confirm: 'Confirm your email address first, using the link that was sent to it.',
    'rate-limited': 'Too many tries. Wait a few minutes and try again.',
    passphrase: 'That isn\'t this account\'s sync passphrase.',
    'short-passphrase': 'Choose a longer sync passphrase: at least 8 characters.',
    raced: 'Another device just turned on sync for this account. Enter the passphrase it set.',
    'weak-password': 'Choose a longer password: at least 8 characters.',
    'email-taken': 'That email already has an account. Sign in instead.',
    'not-found': 'That TV request has run out or was already approved. Start pairing again on the TV.',
    'wrong-tv': 'This link doesn\'t match the TV\'s request. Scan the code on the TV again.',
    session: 'Signed out. Sign in again.',
    refused: 'The sync service refused that request.'
  };
  class PairError extends Error { constructor(code) { super(MESSAGES[code] || MESSAGES.refused); this.code = code; } }

  // ---------- Crypto, as electron/sync-core.js ----------
  async function hkdf(keyBytes, salt, info) {
    const key = await subtle.importKey('raw', keyBytes, 'HKDF', false, ['deriveBits']);
    return new Uint8Array(await subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info: utf8(info) }, key, 256));
  }
  async function keyCheck(syncKeyHex) {
    const check = await hkdf(unhex(syncKeyHex), new Uint8Array(32), CHECK_LABEL);
    const mac = await subtle.importKey('raw', check, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    return b64(await subtle.sign('HMAC', mac, utf8(CHECK_LABEL)));
  }
  async function passphraseKey(passphrase, saltB64, rounds) {
    const text = String(passphrase).normalize('NFC');
    if ([...text].length < 8 || !Number.isInteger(rounds) || rounds < 100000) throw new PairError('short-passphrase');
    const base = await subtle.importKey('raw', utf8(text), 'PBKDF2', false, ['deriveBits']);
    return subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: unb64(saltB64), iterations: rounds }, base, 256);
  }
  // A new account's key, locked with its passphrase, as electron/sync-core.js wrapKey.
  async function wrapKey(syncKeyHex, passphrase, saltB64, rounds, accountId, ivHex) {
    if (!/^[0-9a-f]{64}$/i.test(String(syncKeyHex))) throw new Error('The sync key must be 32 bytes.');
    const key = await subtle.importKey('raw', await passphraseKey(passphrase, saltB64, rounds), 'AES-GCM', false, ['encrypt']);
    const iv = ivHex ? unhex(ivHex) : globalThis.crypto.getRandomValues(new Uint8Array(12));
    const body = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: utf8(`private-tv sync key v1\n${accountId}`) }, key, utf8(String(syncKeyHex).toLowerCase())));
    return b64(concat(new Uint8Array([1]), iv, body));
  }
  async function unwrapKey(wrapped, passphrase, saltB64, rounds, accountId, check) {
    let keyBytes;
    try { keyBytes = await passphraseKey(passphrase, saltB64, rounds); } catch { throw new PairError('passphrase'); }
    const raw = unb64(wrapped);
    if (raw.length < 29 || raw[0] !== 1) throw new PairError('passphrase');
    const key = await subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['decrypt']);
    let plain;
    try { plain = new TextDecoder().decode(await subtle.decrypt({ name: 'AES-GCM', iv: raw.slice(1, 13), additionalData: utf8(`private-tv sync key v1\n${accountId}`) }, key, raw.slice(13))); }
    catch { throw new PairError('passphrase'); }
    if (!/^[0-9a-f]{64}$/.test(plain) || (check !== undefined && await keyCheck(plain) !== check)) throw new PairError('refused');
    return plain;
  }
  function tvKey(publicKey) {
    const raw = unb64(publicKey);
    if (raw.length !== 65 || raw[0] !== 4) throw new PairError('wrong-tv');
    return raw;
  }
  async function checkCode(publicKey) {
    const hash = new DataView(await subtle.digest('SHA-256', tvKey(publicKey)));
    const bits = hash.getUint32(0) >>> 2;
    let out = '';
    for (let i = 5; i >= 0; i--) out += CHECK_LETTERS[(bits >>> (i * 5)) & 31];
    return `${out.slice(0, 3)}-${out.slice(3)}`;
  }
  async function seal(publicKey, pairingId, payload) {
    const tv = await subtle.importKey('raw', tvKey(publicKey), { name: 'ECDH', namedCurve: 'P-256' }, false, []);
    const mine = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
    const shared = new Uint8Array(await subtle.deriveBits({ name: 'ECDH', public: tv }, mine.privateKey, 256));
    const key = await subtle.importKey('raw', await hkdf(shared, utf8(String(pairingId)), LABEL), 'AES-GCM', false, ['encrypt']);
    const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
    const body = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: utf8(`${LABEL}\n${pairingId}`) }, key, utf8(JSON.stringify(payload))));
    return b64(concat(new Uint8Array([1]), new Uint8Array(await subtle.exportKey('raw', mine.publicKey)), iv, body));
  }

  // ---------- The service ----------
  function service(url, key, fetchFn = globalThis.fetch) {
    async function call(method, route, { token, body } = {}) {
      const headers = { apikey: key, 'Content-Type': 'application/json' };
      if (token) headers.Authorization = `Bearer ${token}`;
      let response;
      try { response = await fetchFn(url + route, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), cache: 'no-store', credentials: 'omit', referrerPolicy: 'no-referrer' }); }
      catch { throw new PairError('offline'); }
      let json = null; try { json = await response.json(); } catch { /* empty */ }
      return { status: response.status, json };
    }
    const failed = r => new PairError(r.status === 429 ? 'rate-limited' : r.status >= 500 ? 'unavailable' : r.status === 401 || r.status === 403 ? 'session' : 'refused');
    return {
      async signIn(email, password) {
        const r = await call('POST', '/auth/v1/token?grant_type=password', { body: { email: String(email).trim(), password: String(password) } });
        if (r.status === 200 && r.json?.access_token) return { token: r.json.access_token, accountId: r.json.user?.id };
        if (r.json?.error_code === 'email_not_confirmed') throw new PairError('confirm');
        if (r.status === 400) throw new PairError('login');
        throw failed(r);
      },
      // Creates an account. Supabase emails a confirmation link; the answer never says whether the email had one.
      // backTo: where the email's link lands (this page), if the project allows it.
      async signUp(email, password, backTo) {
        if (String(password).length < 8) throw new PairError('weak-password');
        const route = '/auth/v1/signup' + (backTo ? `?redirect_to=${encodeURIComponent(backTo)}` : '');
        const r = await call('POST', route, { body: { email: String(email).trim(), password: String(password) } });
        if (r.status === 200 && r.json?.access_token) return { confirm: false, session: { token: r.json.access_token, accountId: r.json.user?.id } };
        if (r.status === 200) return { confirm: true };
        const code = String(r.json?.error_code || r.json?.code || '');
        if (code === 'weak_password') throw new PairError('weak-password');
        if (code === 'user_already_exists' || code === 'email_exists') throw new PairError('email-taken');
        throw failed(r);
      },
      // The account's key row, locked with its passphrase, or null before sync is turned on.
      async keyRow(s) {
        const r = await call('GET', '/rest/v1/sync_accounts?select=kdf_rounds,kdf_salt,wrapped_key,key_check', { token: s.token });
        if (r.status !== 200 || !Array.isArray(r.json)) throw failed(r);
        return r.json[0] || null;
      },
      // 'created', or 'exists' when another device turned sync on first.
      async createKeyRow(s, row) {
        const r = await call('POST', '/rest/v1/sync_accounts', { token: s.token, body: row });
        if (r.status === 201) return 'created';
        if (r.status === 409 || r.json?.code === '23505') return 'exists';
        throw failed(r);
      },
      async pair(s, body) {
        const r = await call('POST', '/functions/v1/sync-pair', { token: s.token, body });
        if (r.status === 200) return r.json;
        if (r.status === 404) throw new PairError('not-found');
        throw failed(r);
      },
      async signOut(s) { try { await call('POST', '/auth/v1/logout?scope=local', { token: s.token }); } catch { /* the session ends with its expiry anyway */ } }
    };
  }

  // The request from the TV: { pairingId, publicKey } from the link, or the code typed in.
  function fromLink(hash) {
    const params = new URLSearchParams(String(hash || '').replace(/^#/, ''));
    const pairingId = params.get('p'), publicKey = params.get('k');
    if (!pairingId || !publicKey || !/^[0-9a-f-]{36}$/i.test(pairingId)) return null;
    try { tvKey(publicKey); } catch { return null; }
    return { pairingId, publicKey };
  }
  // Signed in: the TV's request as the service holds it, matched against the link.
  async function findTv(api, s, request) {
    const found = await api.pair(s, request.pairingId ? { action: 'lookup', pairingId: request.pairingId } : { action: 'lookup', code: String(request.code).replace(/\D/g, '') });
    if (request.publicKey && found.publicKey !== request.publicKey) throw new PairError('wrong-tv');
    return { pairingId: found.pairingId, publicKey: found.publicKey, checkCode: await checkCode(found.publicKey) };
  }
  // Approves the TV. For an account without sync yet (create, when the page asked for a new passphrase),
  // this turns it on: a new sync key, locked with the passphrase chosen here, as the Windows app makes it.
  async function approve(api, s, tv, passphrase, create = false) {
    const row = await api.keyRow(s);
    let syncKey;
    if (row) syncKey = await unwrapKey(row.wrapped_key, passphrase, row.kdf_salt, Number(row.kdf_rounds), s.accountId, row.key_check);
    else {
      if (!create) throw new PairError('raced');
      syncKey = hex(globalThis.crypto.getRandomValues(new Uint8Array(32)));
      const salt = b64(globalThis.crypto.getRandomValues(new Uint8Array(16)));
      const made = await api.createKeyRow(s, { kdf: 'pbkdf2-sha256', kdf_rounds: NEW_ROUNDS, kdf_salt: salt, wrapped_key: await wrapKey(syncKey, passphrase, salt, NEW_ROUNDS, s.accountId), key_check: await keyCheck(syncKey) });
      if (made === 'exists') throw new PairError('raced');
    }
    const sealedKey = await seal(tv.publicKey, tv.pairingId, { syncKey, accountId: s.accountId });
    await api.pair(s, { action: 'approve', pairingId: tv.pairingId, sealedKey });
    return { approved: true };
  }
  const NEW_ROUNDS = 600000;
  return { PairError, keyCheck, wrapKey, unwrapKey, checkCode, seal, service, fromLink, findTv, approve, b64, unb64, hex };
})();
if (typeof module !== 'undefined') module.exports = PairPage;

// ---------- The page ----------
if (typeof document !== 'undefined') {
  const $ = id => document.getElementById(id);
  const meta = name => document.querySelector(`meta[name="${name}"]`)?.content || '';
  const api = PairPage.service(meta('sync-url'), meta('sync-key'));
  // The link's # part is read once, then cleared from the address bar and history. It's kept for this
  // tab only (the TV's request ID and public key, nothing secret), so confirming a new account's email
  // and coming back still finds the TV.
  const remembered = () => { try { return JSON.parse(sessionStorage.getItem('tv') || 'null'); } catch { return null; } };
  const forget = () => { try { sessionStorage.removeItem('tv'); } catch { /* fine */ } };
  // Opened from the confirmation email: Supabase adds its own # part (a sign-in for this browser). It's
  // cleared unread; the page where the account was made carries on by itself.
  const fromEmail = /(^|[#&])(type=signup|access_token=|error_code=)/.test(location.hash);
  let linked = fromEmail ? null : PairPage.fromLink(location.hash) || remembered();
  if (linked) { try { sessionStorage.setItem('tv', JSON.stringify(linked)); } catch { /* fine without */ } }
  if (location.hash) history.replaceState(null, '', location.pathname + location.search);
  let session = null, tv = null, newAccount = false, waiting = 0;
  const show = step => { for (const el of document.querySelectorAll('[data-step]')) el.hidden = el.dataset.step !== step; };
  const say = (text, bad = true) => { const el = $('message'); el.textContent = text || ''; el.className = bad ? 'error' : 'note'; };
  const busy = (button, on, label) => { button.disabled = on; if (label) button.textContent = label; };
  const problem = error => error instanceof PairPage.PairError ? error.message : 'Something went wrong on this page. Start again.';
  const setNew = on => { newAccount = on; $('newIntro').hidden = !on; };
  $('codeRow').hidden = Boolean(linked);
  show(fromEmail ? 'confirmed' : 'signin');

  // Signed in: find the TV, then the passphrase. A link that ran out asks for the TV's new code instead,
  // still signed in. From the QR, the link itself names the TV's key, so there's no code to compare.
  async function signedIn(request) {
    try { tv = await PairPage.findTv(api, session, request); }
    catch (error) {
      if (error instanceof PairPage.PairError && (error.code === 'not-found' || error.code === 'wrong-tv')) {
        linked = null; forget(); $('newCode').value = ''; show('tvcode');
        say('The code on the TV has changed. Type the 8-digit code it shows now.');
        return;
      }
      throw error;
    }
    setNew(!(await api.keyRow(session)));
    const scanned = Boolean(request.pairingId);
    $('compare').hidden = scanned; $('checkCode').textContent = tv.checkCode;
    show('approve'); say('');
    $('passphrase').focus();
  }

  $('toSignup').addEventListener('click', () => { $('signupEmail').value = $('email').value; say(''); show('signup'); });
  $('toSignin').addEventListener('click', () => { say(''); show('signin'); });
  $('signupForm').addEventListener('submit', async event => {
    event.preventDefault();
    const button = $('signupGo'); busy(button, true, 'Creating…'); say('');
    const email = $('signupEmail').value, password = $('signupPassword').value;
    try {
      const made = await api.signUp(email, password, location.origin + location.pathname);
      $('signupPassword').value = ''; $('email').value = email;
      if (made.session) { session = made.session; await signedIn(linked || { code: $('tvCode').value }); return; }
      // Waits here for the email link, signing in every few seconds; the password stays in this page only.
      $('sentTo').textContent = email; show('waiting');
      const mine = ++waiting;
      while (mine === waiting) {
        await new Promise(done => setTimeout(done, 4000));
        if (mine !== waiting) return;
        try { session = await api.signIn(email, password); }
        catch (error) { if (error instanceof PairPage.PairError && ['confirm', 'offline', 'unavailable', 'rate-limited'].includes(error.code)) continue; throw error; }
        waiting++;
        if (linked) await signedIn(linked); else { show('tvcode'); say('Email confirmed. Type the 8-digit code on the TV.', false); }
      }
    } catch (error) { waiting++; show('signup'); say(problem(error)); }
    finally { busy(button, false, 'Create account'); }
  });
  $('waitCancel').addEventListener('click', () => { waiting++; show('signup'); say(''); });

  $('signinForm').addEventListener('submit', async event => {
    event.preventDefault();
    const button = $('signinGo'); busy(button, true, 'Signing in…'); say('');
    try {
      const code = $('tvCode').value.replace(/\D/g, '');
      if (!linked && code.length !== 8) throw new PairPage.PairError('not-found');
      session = await api.signIn($('email').value, $('password').value);
      $('password').value = '';
      await signedIn(linked || { code });
    } catch (error) { say(problem(error)); }
    finally { busy(button, false, 'Continue'); }
  });
  $('codeForm').addEventListener('submit', async event => {
    event.preventDefault();
    const button = $('codeGo'); busy(button, true, 'Finding the TV…'); say('');
    try {
      const code = $('newCode').value.replace(/\D/g, '');
      if (code.length !== 8) throw new PairPage.PairError('not-found');
      await signedIn({ code });
    } catch (error) { say(problem(error)); }
    finally { busy(button, false, 'Continue'); }
  });
  $('approveForm').addEventListener('submit', async event => {
    event.preventDefault();
    if (!$('compare').hidden && !$('matches').checked) { say('Check that the TV shows the same code first.'); return; }
    const button = $('approveGo'); busy(button, true, 'Approving…'); say('');
    try {
      await PairPage.approve(api, session, tv, $('passphrase').value, newAccount);
      $('passphrase').value = '';
      await api.signOut(session); session = null; tv = null;
      forget(); say('');
      show('done');
    } catch (error) {
      // Another device turned sync on meanwhile: its passphrase is the one to enter now.
      if (error instanceof PairPage.PairError && error.code === 'raced') { setNew(false); $('passphrase').value = ''; }
      say(problem(error));
    }
    finally { busy(button, false, 'Approve this TV'); }
  });
  $('cancel').addEventListener('click', async () => { if (session) await api.signOut(session); session = null; tv = null; $('passphrase').value = ''; show('signin'); say('Cancelled. Nothing was sent to the TV.', false); });
}
