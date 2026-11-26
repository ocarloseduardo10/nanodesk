/**
 * NanoDesk — Cofre de senhas NATIVO (1.8.9)
 * ==================================================================
 * Substitui a integração por CLI externa (bw) por um cofre 100% embutido:
 *   - Criptografia própria com primitivas PADRÃO da indústria:
 *       KDF: PBKDF2-HMAC-SHA256, 600 000 iterações, salt aleatório 16 B
 *       Cifra: AES-256-GCM (12-byte IV por campo, tag 16 B embutida)
 *   - O cofre é um único arquivo JSON em userData/nanodesk-vault.json
 *     contendo salt, token de verificação e cada campo cifrado por item.
 *   - A chave derivada da senha-mestra vive SÓ na RAM do processo; ao
 *     bloquear (lock) o Buffer é zerado (fill(0)).
 *   - Nenhuma senha, texto plano ou chave é gravada em disco.
 *   - 1.8.11: modo EFÊMERO opcional (vaultEphemeral) — o arquivo nunca é
 *     criado; o cofre vive só na RAM e some ao fechar o NanoDesk.
 *
 * Modelo de ameaça:
 *   - Arquivo em disco → ilegível sem a senha-mestra (AES-256-GCM).
 *   - RAM do processo → a chave existe apenas enquanto desbloqueado.
 *   - Ataque offline com o arquivo → custa 600 k PBKDF2 por tentativa.
 *
 * Isto NÃO é o software Bitwarden; é um cofre nativo do NanoDesk que
 * substitui a antiga ponte por CLI. Mantém o nome do módulo por
 * compatibilidade com require('./bitwarden') em main.js.
 */
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const SCHEMA_VERSION = 1;
const KDF_ITERATIONS = 600000;        // OWASP 2023 para PBKDF2-SHA256
const KEY_LEN = 32;                    // AES-256 → 32 bytes
const SALT_LEN = 16;
const IV_LEN = 12;                     // AES-GCM padrão NIST
const VERIFY_PLAINTEXT = 'NANODESK_VAULT_OK_v1';
const AUTLOCK_DEFAULT_MIN = 15;
const MAX_ITEMS = 5000;

/** Estado em memória (singleton). */
const state = {
  vaultPath: '',
  ephemeral: false,
  memFile: null,
  autolockMinutes: AUTLOCK_DEFAULT_MIN,
  enabled: true,
  derivedKey: null,        // Buffer 32 B ou null quando bloqueado
  unlockedAt: 0,
  lastActivity: 0,
  autolockTimer: null,
  cache: null,             // array de itens decifrados (RAM)
  vaultMeta: null,         // { version, kdf, iterations, salt, verify, verify_iv }
  onChange: null           // callback (notifica renderer para re-render)
};

/* ---------------- helpers baixos ---------------- */

function b64(buf) {
  return Buffer.from(buf).toString('base64');
}
function unb64(str) {
  return Buffer.from(String(str || ''), 'base64');
}

/**
 * Deriva chave 32 B via PBKDF2 a partir da senha-mestra + salt.
 * 1.8.10: versão ASSÍNCRONA (crypto.pbkdf2) — a versão Sync congela a
 * thread do main process por ~400ms (600k iterações), travando todas as
 * abas/animações. Mantemos deriveKeySync interno para os testes que
 * esperam comportamento síncrono, mas as funções públicas
 * createVault/unlock/changeMasterPassword agora aguardam a versão async.
 */
function deriveKey(masterPassword, salt, cb) {
  // retrocompat: se chamarem sem callback, devolve Buffer síncrono
  if (typeof cb !== 'function') return deriveKeySync(masterPassword, salt);
  crypto.pbkdf2(
    Buffer.from(String(masterPassword || ''), 'utf8'),
    salt,
    KDF_ITERATIONS,
    KEY_LEN,
    'sha256',
    cb
  );
}
function deriveKeySync(masterPassword, salt) {
  return crypto.pbkdf2Sync(
    Buffer.from(String(masterPassword || ''), 'utf8'),
    salt,
    KDF_ITERATIONS,
    KEY_LEN,
    'sha256'
  );
}

/** Cifra um texto plano com AES-256-GCM. Retorna {ct, iv} em base64. */
function encryptField(plain, key) {
  if (plain == null) plain = '';
  const iv = crypto.randomBytes(IV_LEN);
  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([c.update(Buffer.from(String(plain), 'utf8')), c.final()]);
  const tag = c.getAuthTag();
  // tag (16 B) é concatenada ao ciphertext para armazenamento compacto.
  const blob = Buffer.concat([ct, tag]);
  return { ct: b64(blob), iv: b64(iv) };
}

/** Decifra um campo {ct, iv} com AES-256-GCM. Retorna string ou null. */
function decryptField(ctB64, ivB64, key) {
  try {
    const blob = unb64(ctB64);
    const iv = unb64(ivB64);
    if (blob.length < 16 || iv.length !== IV_LEN) return '';
    const ct = blob.slice(0, blob.length - 16);
    const tag = blob.slice(blob.length - 16);
    const d = crypto.createDecipheriv('aes-256-gcm', key, iv);
    d.setAuthTag(tag);
    const pt = Buffer.concat([d.update(ct), d.final()]);
    return pt.toString('utf8');
  } catch (_) {
    return '';
  }
}

function randomId() {
  return crypto.randomBytes(12).toString('hex') + '-' + Date.now().toString(36);
}

/**
 * 1.8.11 — casamento de host ESTRITO (a versão anterior vazava credenciais):
 *  - antes: URIs sem esquema usavam `raw.includes(host)` — "banana.com" casava
 *    com "a.com"/"na.com" (domínio do atacante recebia a senha);
 *  - antes: casava nos DOIS sentidos de subdomínio.
 * Agora: (1) URIs sem esquema são normalizadas como https://; (2) só casa host
 * IGUAL ou página que seja SUBDOMÍNIO REAL do host salvo (a.b.example.com casa
 * com example.com; example.com NÃO casa com um login salvo de login.example.com);
 * (3) host salvo sem ponto (com, localhost, TLD) só casa por igualdade.
 */
function normalizeUriHost(raw) {
  let s = String(raw || '').trim();
  if (!s) return '';
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) s = 'https://' + s;
  try {
    const h = new URL(s).hostname.toLowerCase().replace(/\.$/, '').replace(/^www\./, '');
    return h;
  } catch (_) { return ''; }
}

function hostMatches(uriList, host) {
  if (!host || !Array.isArray(uriList)) return false;
  const h = String(host).toLowerCase().replace(/\.$/, '').replace(/^www\./, '');
  if (!h) return false;
  for (const raw of uriList) {
    const hh = normalizeUriHost(raw);
    if (!hh) continue;
    if (hh === h) return true;
    if (hh.indexOf('.') > 0 && h.endsWith('.' + hh)) return true;
  }
  return false;
}

/* ---------------- arquivo do cofre ---------------- */

function readVaultFile() {
  if (state.ephemeral) {   // 1.8.11: cofre efêmero — só RAM
    const m = state.memFile;
    return (m && typeof m === 'object' && Number(m.version) === SCHEMA_VERSION) ? m : null;
  }
  if (!state.vaultPath || !fs.existsSync(state.vaultPath)) return null;
  try {
    const raw = fs.readFileSync(state.vaultPath, 'utf8');
    const obj = JSON.parse(raw);
    if (!obj || typeof obj !== 'object') return null;
    if (Number(obj.version) !== SCHEMA_VERSION) return null;
    return obj;
  } catch (_) {
    return null;
  }
}

function writeVaultFile(obj) {
  if (state.ephemeral) {   // 1.8.11: nada em disco (os itens somem ao fechar o NanoDesk)
    state.memFile = JSON.parse(JSON.stringify(obj));
    return;
  }
  if (!state.vaultPath) throw new Error('Cofre não inicializado (caminho ausente).');
  const dir = path.dirname(state.vaultPath);
  try { fs.mkdirSync(dir, { recursive: true }); } catch (_) { /* já existe */ }
  const tmp = state.vaultPath + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(obj, null, 0), { encoding: 'utf8', mode: 0o600 });
  // renomeio atômico (mesmo volume) — evita cofre corrompido no meio.
  fs.renameSync(tmp, state.vaultPath);
}

/** Reconstrói o JSON do cofre a partir da cache em RAM decifrada. */
function persistFromCache() {
  if (!state.derivedKey || !state.vaultMeta) throw new Error('Cofre bloqueado.');
  const key = state.derivedKey;
  const items = [];
  for (const it of (state.cache || [])) {
    const name = encryptField(it.name || '', key);
    const user = encryptField(it.username || '', key);
    const pass = encryptField(it.password || '', key);
    const uris = encryptField(JSON.stringify(it.uris || []), key);
    const notes = encryptField(it.notes || '', key);
    items.push({
      id: it.id,
      created: Number(it.created) || Date.now(),
      updated: Date.now(),
      name_ct: name.ct, name_iv: name.iv,
      user_ct: user.ct, user_iv: user.iv,
      pass_ct: pass.ct, pass_iv: pass.iv,
      uris_ct: uris.ct, uris_iv: uris.iv,
      notes_ct: notes.ct, notes_iv: notes.iv
    });
  }
  const vault = {
    version: SCHEMA_VERSION,
    kdf: 'pbkdf2-sha256',
    iterations: KDF_ITERATIONS,
    salt: state.vaultMeta.salt,
    verify: state.vaultMeta.verify,
    verify_iv: state.vaultMeta.verify_iv,
    items
  };
  writeVaultFile(vault);
}

/* ---------------- autolock ---------------- */

function clearKey() {
  if (state.derivedKey) {
    try { state.derivedKey.fill(0); } catch (_) { /* ignorado */ }
    state.derivedKey = null;
  }
  state.cache = null;
  state.unlockedAt = 0;
  state.lastActivity = 0;
}

function armAutolock() {
  if (state.autolockTimer) clearTimeout(state.autolockTimer);
  const min = Math.max(1, Number(state.autolockMinutes) || AUTLOCK_DEFAULT_MIN);
  if (!state.enabled || min <= 0) return;
  state.autolockTimer = setTimeout(() => {
    if (state.derivedKey) {
      clearKey();
      if (typeof state.onChange === 'function') {
        try { state.onChange({ event: 'locked' }); } catch (_) { /* ignorado */ }
      }
    }
  }, min * 60 * 1000);
}

function touchActivity() {
  state.lastActivity = Date.now();
  if (state.derivedKey) armAutolock();
}

/* ---------------- API pública ---------------- */

function init(opts) {
  opts = opts || {};
  state.vaultPath = opts.vaultPath ||
    path.join(opts.userDataDir || '', 'nanodesk-vault.json');
  state.autolockMinutes = Math.max(1, Number(opts.autolockMinutes) || AUTLOCK_DEFAULT_MIN);
  state.enabled = opts.enabled !== false;
  state.ephemeral = opts.ephemeral === true;   // 1.8.11: modo efêmero (opt-in)
  state.memFile = null;
  if (typeof opts.onChange === 'function') state.onChange = opts.onChange;
  // Carrega metadados (salt/verify) do arquivo se existir — sem desbloquear.
  state.vaultMeta = null;
  const v = readVaultFile();
  if (v) {
    state.vaultMeta = {
      version: v.version,
      kdf: v.kdf,
      iterations: Number(v.iterations) || KDF_ITERATIONS,
      salt: v.salt,
      verify: v.verify,
      verify_iv: v.verify_iv
    };
  }
}

function exists() {
  return !!readVaultFile();
}

/**
 * 1.8.11 — liga/desliga o modo EFÊMERO (cofre só na RAM). Só troca quando NÃO há cofre
 * no modo atual, para nunca perder senhas nem deixar um cofre órfão no outro modo.
 * @returns {{ok:boolean, reason?:string}}
 */
function setEphemeral(on) {
  const want = on === true;
  if (want === !!state.ephemeral) return { ok: true };
  if (readVaultFile()) {
    return { ok: false, reason: want
      ? 'Já existe um cofre gravado em disco. Para usar o modo temporário, redefina (apague) o cofre atual antes.'
      : 'Há um cofre temporário em uso nesta sessão. Redefina-o antes de voltar ao modo em disco.' };
  }
  lock();
  state.ephemeral = want;
  state.memFile = null;
  state.vaultMeta = null;
  if (!want) {   // voltando ao disco: recarrega metadados de um eventual arquivo existente
    const v = readVaultFile();
    if (v) state.vaultMeta = { version: v.version, kdf: v.kdf, iterations: Number(v.iterations) || KDF_ITERATIONS, salt: v.salt, verify: v.verify, verify_iv: v.verify_iv };
  }
  return { ok: true };
}

function status() {
  return {
    enabled: !!state.enabled,
    initialized: !!state.vaultMeta,
    unlocked: !!state.derivedKey,
    itemCount: state.derivedKey ? (state.cache ? state.cache.length : 0) : 0,
    autolockMinutes: state.autolockMinutes,
    ephemeral: !!state.ephemeral,
    vaultPath: state.ephemeral ? '' : state.vaultPath
  };
}

function setEnabled(v) {
  state.enabled = !!v;
  if (!state.enabled) clearKey();
}

function setAutolockMinutes(n) {
  state.autolockMinutes = Math.max(1, Math.min(720, Math.round(Number(n) || AUTLOCK_DEFAULT_MIN)));
  if (state.derivedKey) armAutolock();
}

/**
 * Cria o cofre pela primeira vez (define senha-mestra).
 * Não desbloqueia automaticamente — o chamador decide.
 * 1.8.10: aceita callback opcional para versão ASSÍNCRONA (PBKDF2
 * async não congela a UI); sem callback, mantém comportamento síncrono.
 */
/**
 * 1.9.2 — força MÍNIMA da senha-mestra (criação e troca; o desbloqueio de cofres antigos não muda).
 * Antes: 6 caracteres. Como a senha-mestra protege TODAS as outras e o arquivo do cofre pode ser copiado
 * para ataque offline, exigimos uma FRASE-SENHA: >= 14 caracteres, variedade mínima e nada de repetição
 * ou "só palavras comuns". (PBKDF2 600k encarece cada tentativa, mas não salva uma senha de 6 caracteres.)
 * @returns {{ok:boolean, reason?:string}}
 */
const MASTER_MIN_LEN = 14;
const COMMON_TOKENS = ['password', 'senha', 'admin', 'qwerty', 'asdf', 'zxcv', 'abcdef', 'abc', 'letmein', 'welcome', 'iloveyou',
  'master', 'nanodesk', 'cofre', 'teste', 'test', 'login', 'user', 'usuario', '0123456789', '123456789', '12345678', '1234567', '123456', '12345', '1234', '123', '000', '111', 'aaa'];
function validateMasterPassword(pw) {
  const s = String(pw == null ? '' : pw);
  const cps = Array.from(s);
  if (cps.length < MASTER_MIN_LEN) {
    return { ok: false, reason: 'A senha-mestra precisa ter ao menos ' + MASTER_MIN_LEN + ' caracteres (use uma frase-senha: 4 palavras ao acaso já bastam).' };
  }
  if (new Set(cps).size < 6) return { ok: false, reason: 'A senha-mestra usa caracteres demais repetidos. Misture mais letras, números ou palavras.' };
  if (/^([\s\S]{1,4})\1+$/u.test(s)) return { ok: false, reason: 'A senha-mestra é um padrão repetido. Escolha algo menos previsível.' };
  // muita variedade fora de a-z/0-9 (acentos, símbolos, emoji, outros alfabetos): a regra de palavras comuns não se aplica
  if (new Set(cps.filter((c) => !/[a-z0-9]/i.test(c))).size >= 4) return { ok: true };
  let rest = s.toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '').replace(/[^a-z0-9]/g, '');
  for (let i = 0; i < 8 && rest; i++) {
    const before = rest;
    for (const t of COMMON_TOKENS) rest = rest.split(t).join('');
    if (rest === before) break;
  }
  if (rest.length < 3) return { ok: false, reason: 'A senha-mestra é formada só por palavras/sequências muito comuns. Escolha uma frase menos previsível.' };
  return { ok: true };
}

function createVault(masterPassword, cb) {
  const strength = validateMasterPassword(masterPassword);
  if (!strength.ok) {
    const err = new Error(strength.reason);
    if (cb) return cb(err);
    throw err;
  }
  const salt = crypto.randomBytes(SALT_LEN);
  const doIt = (key) => {
    const verify = encryptField(VERIFY_PLAINTEXT, key);
    state.vaultMeta = {
      version: SCHEMA_VERSION,
      kdf: 'pbkdf2-sha256',
      iterations: KDF_ITERATIONS,
      salt: b64(salt),
      verify: verify.ct,
      verify_iv: verify.iv
    };
    const vault = Object.assign({}, state.vaultMeta, { items: [] });
    writeVaultFile(vault);
    key.fill(0);
    return true;
  };
  if (typeof cb === 'function') {
    return deriveKey(masterPassword, salt, (err, key) => {
      if (err) return cb(err);
      try { cb(null, doIt(key)); } catch (e) { cb(e); }
    });
  }
  return doIt(deriveKeySync(masterPassword, salt));
}

/**
 * Desbloqueia o cofre derivando a chave da senha-mestra e
 * verificando o token de controle. Em caso de sucesso, decifra
 * todos os itens para a cache em RAM e arma o autolock.
 * 1.8.10: versão async via callback opcional (mesma razão do createVault).
 */
function unlock(masterPassword, cb) {
  const doIt = (key) => {
    const verifyPt = decryptField(state.vaultMeta.verify, state.vaultMeta.verify_iv, key);
    if (verifyPt !== VERIFY_PLAINTEXT) {
      key.fill(0);
      throw new Error('Senha-mestra incorreta.');
    }
    state.derivedKey = key;
    state.unlockedAt = Date.now();
    // decifra todos os itens para RAM
    const raw = readVaultFile();
    const items = (raw && Array.isArray(raw.items)) ? raw.items : [];
    state.cache = items.map(it => ({
      id: String(it.id || randomId()),
      name: decryptField(it.name_ct, it.name_iv, key),
      username: decryptField(it.user_ct, it.user_iv, key),
      password: decryptField(it.pass_ct, it.pass_iv, key),
      uris: (() => { try { return JSON.parse(decryptField(it.uris_ct, it.uris_iv, key) || '[]'); } catch (_) { return []; } })(),
      notes: decryptField(it.notes_ct, it.notes_iv, key),
      created: Number(it.created) || Date.now(),
      updated: Number(it.updated) || Date.now()
    }));
    armAutolock();
    touchActivity();
    return true;
  };
  const ensureMeta = () => {
    if (!state.vaultMeta) {
      const v = readVaultFile();
      if (!v) throw new Error('Nenhum cofre encontrado. Crie um primeiro.');
      state.vaultMeta = {
        version: v.version, kdf: v.kdf,
        iterations: Number(v.iterations) || KDF_ITERATIONS,
        salt: v.salt, verify: v.verify, verify_iv: v.verify_iv
      };
    }
    return unb64(state.vaultMeta.salt);
  };
  if (typeof cb === 'function') {
    let salt;
    try { salt = ensureMeta(); } catch (e) { return cb(e); }
    return deriveKey(masterPassword, salt, (err, key) => {
      if (err) return cb(err);
      try { cb(null, doIt(key)); } catch (e) { cb(e); }
    });
  }
  const salt = ensureMeta();
  return doIt(deriveKeySync(masterPassword, salt));
}

function lock() {
  if (state.autolockTimer) { clearTimeout(state.autolockTimer); state.autolockTimer = null; }
  clearKey();
}

/** Troca a senha-mestra: exige cofre desbloqueado. Reencripta todos os itens.
 *  1.8.10: callback opcional para versão ASSÍNCRONA (PBKDF2 async). */
function changeMasterPassword(oldPw, newPw, cb) {
  if (!state.derivedKey) {
    const err = new Error('Desbloqueie o cofre antes de trocar a senha.');
    if (cb) return cb(err);
    throw err;
  }
  const salt = unb64(state.vaultMeta.salt);
  const doIt = (testKey) => {
    const ok = decryptField(state.vaultMeta.verify, state.vaultMeta.verify_iv, testKey) === VERIFY_PLAINTEXT;
    testKey.fill(0);
    if (!ok) throw new Error('Senha-mestra atual incorreta.');
    { const st = validateMasterPassword(newPw); if (!st.ok) throw new Error(st.reason); }
  };
  const applyNewKey = (newKey, finalSalt) => {
    const newVerify = encryptField(VERIFY_PLAINTEXT, newKey);
    if (state.derivedKey) state.derivedKey.fill(0);
    state.derivedKey = newKey;
    state.vaultMeta.salt = b64(finalSalt); // salt que foi usado para derivar newKey
    state.vaultMeta.verify = newVerify.ct;
    state.vaultMeta.verify_iv = newVerify.iv;
    persistFromCache();
    armAutolock();
    touchActivity();
    return true;
  };
  // passo 1: validar senha antiga (precisa derivar a chave com sync — pequeno)
  // passo 2: derivar nova chave async (caro, ~400ms)
  const newSalt = crypto.randomBytes(SALT_LEN);
  if (typeof cb === 'function') {
    let testKey;
    try { testKey = deriveKeySync(oldPw, salt); doIt(testKey); }
    catch (e) { return cb(e); }
    return deriveKey(newPw, newSalt, (err, newKey) => {
      if (err) return cb(err);
      try { cb(null, applyNewKey(newKey, newSalt)); } catch (e) { cb(e); }
    });
  }
  const testKey = deriveKeySync(oldPw, salt);
  doIt(testKey);
  const newKey = deriveKeySync(newPw, newSalt);
  return applyNewKey(newKey, newSalt);
}

/* ---------------- CRUD ---------------- */

function list() {
  if (!state.derivedKey) throw new Error('Cofre bloqueado.');
  touchActivity();
  return (state.cache || []).map(sanitizeItem);
}

function search(query) {
  if (!state.derivedKey) throw new Error('Cofre bloqueado.');
  touchActivity();
  const q = String(query || '').trim().toLowerCase();
  if (!q) return list();
  return (state.cache || [])
    .filter(it => {
      if ((it.name || '').toLowerCase().includes(q)) return true;
      if ((it.username || '').toLowerCase().includes(q)) return true;
      if ((it.notes || '').toLowerCase().includes(q)) return true;
      if (Array.isArray(it.uris) && it.uris.some(u => String(u).toLowerCase().includes(q))) return true;
      return false;
    })
    .map(sanitizeItem);
}

function getByHost(host) {
  if (!state.derivedKey) throw new Error('Cofre bloqueado.');
  touchActivity();
  return (state.cache || [])
    .filter(it => hostMatches(it.uris, host))
    .map(sanitizeItem);
}

function getOne(id) {
  if (!state.derivedKey) throw new Error('Cofre bloqueado.');
  touchActivity();
  const it = (state.cache || []).find(x => x.id === String(id));
  return it ? sanitizeItem(it) : null;
}

function add(item) {
  if (!state.derivedKey) throw new Error('Cofre bloqueado.');
  if (state.cache.length >= MAX_ITEMS) throw new Error('Cofre cheio (' + MAX_ITEMS + ' itens).');
  const now = Date.now();
  const rec = {
    id: randomId(),
    name: String((item && item.name) || '').slice(0, 200),
    username: String((item && item.username) || '').slice(0, 500),
    password: String((item && item.password) || ''),
    uris: Array.isArray(item && item.uris)
      ? item.uris.map(u => String(u || '').slice(0, 1000)).filter(Boolean).slice(0, 10)
      : [],
    notes: String((item && item.notes) || '').slice(0, 8000),
    created: now,
    updated: now
  };
  state.cache.push(rec);
  persistFromCache();
  touchActivity();
  return sanitizeItem(rec);
}

function update(id, patch) {
  if (!state.derivedKey) throw new Error('Cofre bloqueado.');
  const it = (state.cache || []).find(x => x.id === String(id));
  if (!it) throw new Error('Item não encontrado.');
  if (patch) {
    if ('name' in patch) it.name = String(patch.name || '').slice(0, 200);
    if ('username' in patch) it.username = String(patch.username || '').slice(0, 500);
    if ('password' in patch) it.password = String(patch.password || '');
    if ('uris' in patch) it.uris = Array.isArray(patch.uris)
      ? patch.uris.map(u => String(u || '').slice(0, 1000)).filter(Boolean).slice(0, 10) : [];
    if ('notes' in patch) it.notes = String(patch.notes || '').slice(0, 8000);
    it.updated = Date.now();
  }
  persistFromCache();
  touchActivity();
  return sanitizeItem(it);
}

function remove(id) {
  if (!state.derivedKey) throw new Error('Cofre bloqueado.');
  const before = state.cache.length;
  state.cache = state.cache.filter(x => x.id !== String(id));
  if (state.cache.length === before) throw new Error('Item não encontrado.');
  persistFromCache();
  touchActivity();
  return true;
}

function sanitizeItem(it) {
  return {
    id: it.id,
    name: it.name || '',
    username: it.username || '',
    password: it.password || '',
    uris: Array.isArray(it.uris) ? it.uris : [],
    notes: it.notes || '',
    created: it.created || 0,
    updated: it.updated || 0
  };
}

/* ---------------- gerador de senhas ---------------- */

function generatePassword(opts) {
  opts = opts || {};
  const len = Math.max(4, Math.min(256, Number(opts.length) || 24));
  const groups = [];
  if (opts.lowercase !== false) groups.push('abcdefghijklmnopqrstuvwxyz');
  if (opts.uppercase !== false) groups.push('ABCDEFGHJKLMNPQRSTUVWXYZ');
  if (opts.digits !== false) groups.push('0123456789');
  if (opts.symbols !== false) groups.push('!@#$%^&*-_=+?.,:;');
  if (!groups.length) groups.push('abcdefghijklmnopqrstuvwxyz');
  const pool = groups.join('');
  const out = [];
  // garante ao menos 1 de cada grupo selecionado
  for (const g of groups) out.push(g[crypto.randomInt(g.length)]);
  // preenche o resto
  for (let i = out.length; i < len; i++) out.push(pool[crypto.randomInt(pool.length)]);
  // embaralha (Fisher-Yates com randomInt)
  for (let i = out.length - 1; i > 0; i--) {
    const j = crypto.randomInt(i + 1);
    const tmp = out[i]; out[i] = out[j]; out[j] = tmp;
  }
  return out.join('');
}

/* ---------------- export / import (backup) ---------------- */

function exportJson() {
  if (!state.derivedKey) throw new Error('Cofre bloqueado.');
  touchActivity();
  return JSON.stringify({
    exportedAt: new Date().toISOString(),
    application: 'NanoDesk',
    schema: SCHEMA_VERSION,
    items: (state.cache || []).map(sanitizeItem)
  }, null, 2);
}

function importJson(jsonStr, mode) {
  if (!state.derivedKey) throw new Error('Cofre bloqueado.');
  let arr;
  try {
    const obj = JSON.parse(String(jsonStr || ''));
    arr = Array.isArray(obj) ? obj : (obj && Array.isArray(obj.items) ? obj.items : null);
  } catch (_) { throw new Error('Arquivo de importação ilegível.'); }
  if (!arr) throw new Error('Nenhum item encontrado no arquivo.');
  const replace = mode === 'replace';
  if (replace) state.cache = [];
  let added = 0;
  for (const raw of arr) {
    if (state.cache.length >= MAX_ITEMS) break;
    if (!raw || typeof raw !== 'object') continue;
    const now = Date.now();
    state.cache.push({
      id: randomId(),
      name: String(raw.name || '').slice(0, 200),
      username: String(raw.username || '').slice(0, 500),
      password: String(raw.password || ''),
      uris: Array.isArray(raw.uris) ? raw.uris.map(u => String(u || '').slice(0, 1000)).filter(Boolean).slice(0, 10) : [],
      notes: String(raw.notes || '').slice(0, 8000),
      created: now, updated: now
    });
    added++;
  }
  persistFromCache();
  touchActivity();
  return { added, total: state.cache.length };
}

/** Apaga o cofre por completo (usado por "redefinir cofre"). */
function destroy() {
  lock();
  state.vaultMeta = null;
  state.memFile = null;
  if (state.vaultPath && !state.ephemeral) {
    try { fs.unlinkSync(state.vaultPath); } catch (_) { /* já não existia */ }
  }
  return true;
}

/* ---------------- script de preenchimento (injecão no mundo principal) ---------------- */

/**
 * Script que preenche o primeiro formulário de login visível com
 * usuário/senha. Executado via webContents.executeJavaScript no MAIN world.
 * Mantém a assinatura da versão CLI antiga (compatibilidade com main.js).
 */
function fillScript(username, password) {
  const u = JSON.stringify(String(username || ''));
  const p = JSON.stringify(String(password || ''));
  return (
    '(function(){' +
    'try {' +
    '  function native(el, val){' +
    '    var proto = el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;' +
    '    var set = Object.getOwnPropertyDescriptor(proto, "value").set;' +
    '    if (!set) { el.value = val; } else { set.call(el, val); }' +
    '    el.dispatchEvent(new Event("input", { bubbles: true }));' +
    '    el.dispatchEvent(new Event("change", { bubbles: true }));' +
    '  }' +
    '  function visible(el){ try { var r = el.getBoundingClientRect(); return r.width > 0 && r.height > 0; } catch(_) { return false; } }' +
    '  var pw = Array.from(document.querySelectorAll("input[type=password]")).filter(visible)[0];' +
    '  if (!pw) return { ok:false, reason:"nenhum campo de senha visivel" };' +
    '  var form = pw.closest("form") || document;' +
    '  var user = Array.from(form.querySelectorAll("input[type=text],input[type=email],input:not([type]),input[type=tel]"))' +
    '    .filter(visible)[0];' +
    '  var filled = [];' +
    '  if (user) { native(user, ' + u + '); filled.push("usuario"); }' +
    '  native(pw, ' + p + '); filled.push("senha");' +
    '  pw.focus();' +
    '  return { ok:true, filled: filled };' +
    '} catch (e) { return { ok:false, reason:String(e && e.message || e) }; }' +
    '})();'
  );
}

module.exports = {
  // ciclo de vida
  init, exists, status, setEphemeral,
  setEnabled, setAutolockMinutes,
  createVault, unlock, lock, changeMasterPassword, destroy, validateMasterPassword, MASTER_MIN_LEN,
  // CRUD
  list, search, getByHost, getOne, add, update, remove, hostMatches,
  // ferramentas
  generatePassword, exportJson, importJson,
  // preenchimento
  fillScript,
  // constantes expostas (para testes)
  SCHEMA_VERSION, KDF_ITERATIONS
};
