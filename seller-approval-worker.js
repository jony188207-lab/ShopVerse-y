/**
 * ShopVerse seller-approval API (Cloudflare Worker, free plan). A free replacement for the Cloud Function `reviewSellerApplication`
 * (which needs the Firebase Blaze plan). One file, no dependencies, so it can also be pasted into the Cloudflare dashboard.
 *
 * Trust model
 *  1. The browser sends its Firebase ID token. The Worker verifies it (RS256, Google's public keys, audience = project id). No secret is needed for this.
 *  2. The Worker reads roles/{uid} with its own service account and accepts only `admin` / `super_admin` (same source the Firestore rules use).
 *  3. Only then does it write, using the service account (server side, bypasses rules) inside a Firestore transaction, exactly like the Cloud Function.
 *  The service-account key lives ONLY in the Worker secret SERVICE_ACCOUNT_JSON. It is never sent to a browser and never logged.
 *
 * Environment:  FIREBASE_PROJECT_ID (var) · ALLOWED_ORIGINS (var, comma separated) · SERVICE_ACCOUNT_JSON (SECRET)
 */

const JWKS_URL = 'https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com';
const TOKEN_URL = 'https://oauth2.googleapis.com/token';
const ADMIN_ROLES = ['admin', 'super_admin'];
const ACTIONS = ['approve', 'reject', 'suspend', 'reactivate'];
const STATUS = { 'invalid-argument': 400, unauthenticated: 401, 'permission-denied': 403, 'not-found': 404, 'already-exists': 409, 'failed-precondition': 409, aborted: 409, internal: 500 };

class HttpError extends Error { constructor(code, message) { super(message); this.code = code; } }
const fail = (code, message) => { throw new HttpError(code, message); };

/* ---------- small helpers ---------- */
const te = new TextEncoder();
const td = new TextDecoder();
const b64u = (buf) => { let s = ''; for (const c of new Uint8Array(buf)) s += String.fromCharCode(c); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); };
const unb64u = (s) => { const t = s.replace(/-/g, '+').replace(/_/g, '/'); const bin = atob(t + '='.repeat((4 - (t.length % 4)) % 4)); return Uint8Array.from(bin, (c) => c.charCodeAt(0)); };
const jsonPart = (p) => JSON.parse(td.decode(unb64u(p)));
const clean = (v, max) => (typeof v === 'string' ? v.trim().slice(0, max) : '');
function autoId() {
  const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let id = '';
  while (id.length < 20) for (const b of crypto.getRandomValues(new Uint8Array(32))) if (b < 248 && id.length < 20) id += A[b % 62];
  return id;
}

/* ---------- Firestore value encoding (REST JSON) ---------- */
function enc(v) {
  if (v === null || v === undefined) return { nullValue: null };
  if (v instanceof Date) return { timestampValue: v.toISOString() };
  if (typeof v === 'string') return { stringValue: v };
  if (typeof v === 'boolean') return { booleanValue: v };
  if (typeof v === 'number') return Number.isInteger(v) ? { integerValue: String(v) } : { doubleValue: v };
  if (Array.isArray(v)) return { arrayValue: { values: v.map(enc) } };
  return { mapValue: { fields: encFields(v) } };
}
const encFields = (o) => Object.fromEntries(Object.entries(o).filter(([, x]) => x !== undefined).map(([k, x]) => [k, enc(x)]));
function dec(v) {
  if (!v) return null;
  if ('stringValue' in v) return v.stringValue;
  if ('integerValue' in v) return Number(v.integerValue);
  if ('doubleValue' in v) return v.doubleValue;
  if ('booleanValue' in v) return v.booleanValue;
  if ('timestampValue' in v) return new Date(v.timestampValue);
  if ('arrayValue' in v) return (v.arrayValue.values ?? []).map(dec);
  if ('mapValue' in v) return decFields(v.mapValue.fields ?? {});
  return null;
}
const decFields = (f) => Object.fromEntries(Object.entries(f ?? {}).map(([k, x]) => [k, dec(x)]));

/* ---------- 1. Firebase ID token verification ---------- */
let jwks = { at: 0, tried: 0, keys: new Map() };
async function signingKey(kid) {
  const now = Date.now();
  if (!(jwks.keys.has(kid) && now - jwks.at < 3600_000) && now - jwks.tried > 60_000) {
    jwks.tried = now;
    const res = await fetch(JWKS_URL);
    if (!res.ok) fail('internal', 'Could not load Google signing keys.');
    const { keys = [] } = await res.json();
    const map = new Map();
    for (const jwk of keys) map.set(jwk.kid, await crypto.subtle.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']));
    jwks = { at: now, tried: now, keys: map };
  }
  return jwks.keys.get(kid);
}

async function verifyIdToken(token, projectId) {
  const bad = () => fail('unauthenticated', 'Sign in again.');
  const parts = token.split('.');
  if (parts.length !== 3) bad();
  let header, payload;
  try { header = jsonPart(parts[0]); payload = jsonPart(parts[1]); } catch { bad(); }
  if (header.alg !== 'RS256' || typeof header.kid !== 'string') bad();
  const key = await signingKey(header.kid);
  if (!key) bad();
  const ok = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, unb64u(parts[2]), te.encode(`${parts[0]}.${parts[1]}`));
  if (!ok) bad();
  const now = Math.floor(Date.now() / 1000);
  if (payload.aud !== projectId || payload.iss !== `https://securetoken.google.com/${projectId}`) bad();
  if (typeof payload.sub !== 'string' || !payload.sub || payload.sub.length > 128) bad();
  if (typeof payload.exp !== 'number' || payload.exp <= now) bad();
  if (typeof payload.iat === 'number' && payload.iat > now + 300) bad();
  return payload.sub;
}

/* ---------- 2. Service-account access token (server side only) ---------- */
let sa = { tok: '', exp: 0 };
async function accessToken(env) {
  const now = Math.floor(Date.now() / 1000);
  if (sa.tok && sa.exp - 60 > now) return sa.tok;
  let key;
  try { key = JSON.parse(env.SERVICE_ACCOUNT_JSON); } catch { key = null; }
  if (!key || typeof key.client_email !== 'string' || typeof key.private_key !== 'string') fail('internal', 'The approval service is not configured (service account secret missing or invalid).');
  if (key.project_id && key.project_id !== env.FIREBASE_PROJECT_ID) fail('internal', 'The service account belongs to a different Firebase project.');
  const der = unb64u(key.private_key.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''));
  const priv = await crypto.subtle.importKey('pkcs8', der, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign']);
  const head = b64u(te.encode(JSON.stringify({ alg: 'RS256', typ: 'JWT' })));
  const claims = b64u(te.encode(JSON.stringify({ iss: key.client_email, scope: 'https://www.googleapis.com/auth/cloud-platform', aud: TOKEN_URL, iat: now, exp: now + 3600 })));
  const sig = b64u(await crypto.subtle.sign('RSASSA-PKCS1-v1_5', priv, te.encode(`${head}.${claims}`)));
  const res = await fetch(TOKEN_URL, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: `grant_type=${encodeURIComponent('urn:ietf:params:oauth:grant-type:jwt-bearer')}&assertion=${head}.${claims}.${sig}` });
  if (!res.ok) { console.error('service account token request failed', res.status); fail('internal', 'Could not authenticate the approval service with Google.'); }
  const j = await res.json();
  sa = { tok: j.access_token, exp: now + Number(j.expires_in || 3600) };
  return sa.tok;
}

/* ---------- 3. Firestore REST client ---------- */
function firestore(env, token) {
  const root = `projects/${env.FIREBASE_PROJECT_ID}/databases/(default)/documents`;
  const base = `https://firestore.googleapis.com/v1/${root}`;
  const name = (path) => `${root}/${path}`;
  async function call(method, url, body) {
    const res = await fetch(url, { method, headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) });
    if (res.status === 404 && method === 'GET') return null;
    const text = await res.text();
    let json = {};
    try { json = text ? JSON.parse(text) : {}; } catch { /* keep {} */ }
    if (!res.ok) {
      if (res.status === 409 || json?.error?.status === 'ABORTED') fail('aborted', 'The data changed while saving. Try again.');
      console.error('firestore error', method, res.status, json?.error?.status);
      fail('internal', `The database request failed (${res.status}).`);
    }
    return json;
  }
  return {
    name,
    async get(path, txn) {
      const d = await call('GET', `${base}/${path}${txn ? `?transaction=${encodeURIComponent(txn)}` : ''}`);
      return d ? decFields(d.fields) : null;
    },
    async query(collectionId, filter, txn, limit) {
      const structuredQuery = { from: [{ collectionId }], where: filter, ...(limit ? { limit } : {}) };
      const rows = await call('POST', `${base}:runQuery`, { structuredQuery, ...(txn ? { transaction: txn } : {}) });
      return (rows ?? []).filter((r) => r.document).map((r) => ({ path: r.document.name.slice(root.length + 1), data: decFields(r.document.fields) }));
    },
    begin: async () => (await call('POST', `${base}:beginTransaction`, { options: { readWrite: {} } })).transaction,
    commit: (writes, txn) => call('POST', `${base}:commit`, { writes, ...(txn ? { transaction: txn } : {}) }),
    rollback: (txn) => call('POST', `${base}:rollback`, { transaction: txn }).catch(() => null),
  };
}
const eq = (field, value) => ({ fieldFilter: { field: { fieldPath: field }, op: 'EQUAL', value: enc(value) } });
const inList = (field, values) => ({ fieldFilter: { field: { fieldPath: field }, op: 'IN', value: enc(values) } });
const and = (...filters) => ({ compositeFilter: { op: 'AND', filters } });
// Write builders: setDoc replaces the whole document; patchDoc changes only the listed fields (a mask entry without a value deletes that field).
const setDoc = (fs, path, data, exists) => ({ update: { name: fs.name(path), fields: encFields(data) }, ...(exists === undefined ? {} : { currentDocument: { exists } }) });
const patchDoc = (fs, path, data, extraMask = []) => ({ update: { name: fs.name(path), fields: encFields(data) }, updateMask: { fieldPaths: [...Object.keys(data), ...extraMask] }, currentDocument: { exists: true } });

/* ---------- 4. The business logic (a faithful port of functions/src/seller.ts) ---------- */
async function settingsCommission(fs) {
  const d = (await fs.get('platformSettings/main')) ?? {};
  return typeof d.commissionDefaultPercent === 'number' && d.commissionDefaultPercent >= 0 && d.commissionDefaultPercent <= 50 ? d.commissionDefaultPercent : 10;
}

async function applicantEmailVerified(env, token, uid) {
  const res = await fetch(`https://identitytoolkit.googleapis.com/v1/projects/${env.FIREBASE_PROJECT_ID}/accounts:lookup`, {
    method: 'POST', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ localId: [uid] }),
  });
  if (!res.ok) { console.error('accounts:lookup failed', res.status); fail('internal', 'Could not read the applicant from Firebase Authentication. Check the service account has the Firebase Authentication Viewer role, then retry.'); }
  const j = await res.json();
  return j.users?.[0]?.emailVerified === true; // no such user => unverified
}

async function setStoreProductsHidden(fs, storeId, hide) {
  let total = 0;
  for (let round = 0; round < 50; round++) {
    const filter = hide ? and(eq('storeId', storeId), inList('status', ['approved', 'out_of_stock'])) : and(eq('storeId', storeId), eq('suspendReason', 'store_suspended'));
    const docs = await fs.query('products', filter, null, 400);
    if (!docs.length) return total;
    const now = new Date();
    await fs.commit(docs.map((d) => (hide
      ? patchDoc(fs, d.path, { status: 'suspended', suspendReason: 'store_suspended', updatedAt: now })
      : patchDoc(fs, d.path, { status: Number(d.data.stock) > 0 ? 'approved' : 'out_of_stock', updatedAt: now }, ['suspendReason']))));
    total += docs.length;
    if (docs.length < 400) return total;
  }
  return total;
}

const MESSAGES = {
  approve: (name) => ({ title: 'Your store is approved', body: `“${name}” is live. Open the Seller Center to add products.`, link: '/seller' }),
  reject: (_n, note) => ({ title: 'Seller application not approved', body: note, link: '/become-seller' }),
  suspend: (_n, note) => ({ title: 'Your store was suspended', body: note, link: '/become-seller' }),
  reactivate: (name) => ({ title: 'Your store was reactivated', body: `“${name}” is open again.`, link: '/seller' }),
};

export async function reviewSellerApplication({ env, token, adminId, input }) {
  const fs = firestore(env, token);
  const { applicationId: uid, action: act } = input;
  const note = clean(input.note, 500);
  if (typeof uid !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(uid)) fail('invalid-argument', 'Missing application.');
  if (!ACTIONS.includes(act)) fail('invalid-argument', 'Unknown action.');
  if ((act === 'reject' || act === 'suspend') && note.length < 5) fail('invalid-argument', 'Give a reason (at least 5 characters). The applicant will see it.');
  const defaultCommission = await settingsCommission(fs);
  let storeId = '';
  let storeName = '';

  for (let attempt = 0; ; attempt++) {
    const txn = await fs.begin();
    try {
      const app = await fs.get(`sellerApplications/${uid}`, txn);
      if (!app) fail('not-found', 'Application not found.');
      const status = app.status;
      const roleDoc = await fs.get(`roles/${uid}`, txn);
      const role = roleDoc ? String(roleDoc.role) : 'user';
      const storeQ = await fs.query('stores', eq('ownerId', uid), txn, 1);
      const now = new Date();
      const decision = { reviewNote: note, reviewedBy: adminId, reviewedAt: now, updatedAt: now };
      storeName = String(app.storeName ?? '');
      const writes = [];

      if (act === 'approve') {
        if (status !== 'pending') fail('failed-precondition', `Only pending applications can be approved (this one is ${status}).`);
        if (!(await applicantEmailVerified(env, token, uid))) fail('failed-precondition', 'The applicant has not verified their email yet. Ask them to verify it, then approve.');
        if (role !== 'user') fail('failed-precondition', `This account already has the “${role}” role and cannot be converted to a seller.`);
        if (storeQ.length) fail('failed-precondition', 'This account already owns a store.');
        const slugQ = await fs.query('stores', eq('slug', app.slug), txn, 1);
        if (slugQ.length) fail('already-exists', `The store address “${app.slug}” is already taken. Reject with a note asking for a different slug.`);
        storeId = autoId();
        writes.push(
          setDoc(fs, `stores/${storeId}`, {
            ownerId: uid, applicationId: uid, name: app.storeName, slug: app.slug, description: app.description ?? '', logoUrl: app.logoUrl ?? '', bannerUrl: app.bannerUrl ?? '',
            city: app.city, country: app.country, returnPolicy: app.returnPolicy ?? '', shippingInfo: app.shippingInfo ?? '', shippingFee: 0,
            status: 'approved', ratingAvg: 0, ratingCount: 0, ratingSum: 0, followerCount: 0, salesCount: 0, createdAt: now, updatedAt: now,
          }, false),
          setDoc(fs, `storeFinance/${storeId}`, { commissionRate: defaultCommission, updatedAt: now }, false),
          setDoc(fs, `storePrivate/${storeId}`, { phone: app.phone, email: app.email, address: app.address, createdAt: now, updatedAt: now }, false),
          setDoc(fs, `roles/${uid}`, { role: 'seller', updatedAt: now, updatedBy: adminId }),
          patchDoc(fs, `sellerApplications/${uid}`, { status: 'approved', storeId, ...decision }),
        );
      } else if (act === 'reject') {
        if (status !== 'pending') fail('failed-precondition', `Only pending applications can be rejected (this one is ${status}).`);
        writes.push(patchDoc(fs, `sellerApplications/${uid}`, { status: 'rejected', ...decision }));
      } else if (act === 'suspend') {
        if (status !== 'approved' || !storeQ.length) fail('failed-precondition', 'Only approved sellers can be suspended.');
        storeId = storeQ[0].path.split('/')[1];
        writes.push(patchDoc(fs, storeQ[0].path, { status: 'suspended', updatedAt: now }));
        if (role === 'seller') writes.push(setDoc(fs, `roles/${uid}`, { role: 'user', updatedAt: now, updatedBy: adminId }));
        writes.push(patchDoc(fs, `sellerApplications/${uid}`, { status: 'suspended', ...decision }));
      } else {
        if (status !== 'suspended' || !storeQ.length) fail('failed-precondition', 'Only suspended sellers can be reactivated.');
        if (role !== 'user' && role !== 'seller') fail('failed-precondition', `The account now has the “${role}” role.`);
        storeId = storeQ[0].path.split('/')[1];
        writes.push(patchDoc(fs, storeQ[0].path, { status: 'approved', updatedAt: now }), setDoc(fs, `roles/${uid}`, { role: 'seller', updatedAt: now, updatedBy: adminId }), patchDoc(fs, `sellerApplications/${uid}`, { status: 'approved', ...decision }));
      }
      await fs.commit(writes, txn);
      break;
    } catch (e) {
      if (e instanceof HttpError && e.code === 'aborted' && attempt < 3) continue; // optimistic-concurrency retry
      await fs.rollback(txn);
      throw e;
    }
  }

  let products = 0;
  if (act === 'suspend') products = await setStoreProductsHidden(fs, storeId, true);
  if (act === 'reactivate') products = await setStoreProductsHidden(fs, storeId, false);
  const now = new Date();
  await fs.commit([setDoc(fs, `adminLogs/${autoId()}`, { adminId, action: `seller.${act}`, targetType: 'sellerApplication', targetId: uid, storeId, note, products, via: 'cloudflare-worker', createdAt: now }, false)]);
  try { // in-app notification (mandatory "system" category, so no preference check is needed); push messages are not sent by the Worker
    const m = MESSAGES[act](storeName, note);
    await fs.commit([setDoc(fs, `notifications/${autoId()}`, { userId: uid, type: `seller_${act}`, category: 'system', title: m.title.slice(0, 100), body: String(m.body).slice(0, 300), image: '', relatedId: '', relatedType: '', link: m.link, read: false, createdAt: now }, false)]);
  } catch (e) { console.error('notification failed', e instanceof HttpError ? e.code : 'error'); }
  return { ok: true, storeId, products };
}

/* ---------- 5. HTTP layer ---------- */
function corsHeaders(request, env) {
  const origin = request.headers.get('Origin');
  const allowed = String(env.ALLOWED_ORIGINS ?? '').split(',').map((s) => s.trim().replace(/\/$/, '')).filter(Boolean);
  const h = { Vary: 'Origin' };
  if (origin && allowed.includes(origin)) Object.assign(h, { 'Access-Control-Allow-Origin': origin, 'Access-Control-Allow-Headers': 'Authorization, Content-Type', 'Access-Control-Allow-Methods': 'POST, OPTIONS', 'Access-Control-Max-Age': '86400' });
  return h;
}
const json = (status, body, extra) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', ...extra } });

export async function handle(request, env) {
  const cors = corsHeaders(request, env);
  const url = new URL(request.url);
  try {
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });
    if (request.method === 'GET' && url.pathname === '/') return json(200, { ok: true, service: 'shopverse-seller-approval' }, cors);
    if (url.pathname !== '/seller/review') fail('not-found', 'Not found.');
    if (request.method !== 'POST') fail('invalid-argument', 'Use POST.');
    if (!env.FIREBASE_PROJECT_ID || !env.ALLOWED_ORIGINS) fail('internal', 'The approval service is not configured (FIREBASE_PROJECT_ID / ALLOWED_ORIGINS).');
    const origin = request.headers.get('Origin');
    if (origin && !cors['Access-Control-Allow-Origin']) fail('permission-denied', 'This website is not allowed to use the approval service.');

    const auth = request.headers.get('Authorization') ?? '';
    if (!auth.startsWith('Bearer ')) fail('unauthenticated', 'Sign in first.');
    const uid = await verifyIdToken(auth.slice(7).trim(), env.FIREBASE_PROJECT_ID);

    const token = await accessToken(env);
    const roleDoc = await firestore(env, token).get(`roles/${uid}`);
    if (!roleDoc || !ADMIN_ROLES.includes(String(roleDoc.role))) fail('permission-denied', 'You do not have permission to do that.');

    let input;
    try { input = await request.json(); } catch { fail('invalid-argument', 'Invalid request.'); }
    if (!input || typeof input !== 'object') fail('invalid-argument', 'Invalid request.');
    return json(200, await reviewSellerApplication({ env, token, adminId: uid, input }), cors);
  } catch (e) {
    if (e instanceof HttpError) return json(STATUS[e.code] ?? 500, { error: { code: e.code, message: e.message } }, cors);
    console.error('unexpected error', e instanceof Error ? e.name : 'unknown');
    return json(500, { error: { code: 'internal', message: 'Unexpected error.' } }, cors);
  }
}

export function __resetCachesForTests() { jwks = { at: 0, tried: 0, keys: new Map() }; sa = { tok: '', exp: 0 }; }
export default { fetch: (request, env) => handle(request, env) };
