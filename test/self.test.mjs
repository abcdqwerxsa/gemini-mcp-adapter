// Self-checks for the adapter's security-relevant logic.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { test } from 'node:test';
import { createOAuth, GOOGLE_REDIRECT_RE, hashPassword, jwt, jwtVerify, safeEqual, verifyPassword } from '../src/oauth.mjs';
import { stripOutputSchema } from '../src/upstream.mjs';
import { load, update, save, newSecret } from '../src/config.mjs';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const key = crypto.createHash('sha256').update('k').digest();
const G_URI = 'https://oauth-redirect.googleusercontent.com/r/user_bound_custom-mcp-d9d9d6165bd340bea77cc9ac';
const VERIFIER = crypto.randomBytes(32).toString('base64url');
const CHALLENGE = crypto.createHash('sha256').update(VERIFIER).digest('base64url');

const mk = (over = {}) =>
  createOAuth({
    getClients: () => [{ id: 'gemini', secret: 's3cret' }],
    jwtKey: () => key,
    issuer: 'gma',
    get accessTtl() { return 60; },
    get refreshTtl() { return 3600; },
    get allowDcr() { return !!over.allowDcr; },
    redirectAllowed: (uri, c) => (c.redirectUris ?? []).includes(uri) || GOOGLE_REDIRECT_RE.test(uri),
    ...over,
  });

test('jwt roundtrip, tamper, expiry, wrong key/issuer', () => {
  const now = Math.floor(Date.now() / 1000);
  const t = jwt({ iss: 'gma', sub: 'c', exp: now + 60, typ: 'refresh' }, key);
  assert.equal(jwtVerify(t, key, 'gma')?.sub, 'c');
  assert.equal(jwtVerify(t.slice(0, -3) + 'AAA', key, 'gma'), null);
  assert.equal(jwtVerify(jwt({ iss: 'gma', sub: 'c', exp: now - 1 }, key), key, 'gma'), null);
  assert.equal(jwtVerify(t, Buffer.alloc(32), 'gma'), null);
  assert.equal(jwtVerify(t, key, 'other'), null);
  assert.equal(jwtVerify('not.a.jwt', key, 'gma'), null);
  assert.ok(safeEqual('abc', 'abc') && !safeEqual('abc', 'abd') && !safeEqual('abc', 'abcd'));
});

test('redirect allowlist: Google variants only', () => {
  for (const u of ['https://oauth-redirect.googleusercontent.com/r/abc', 'https://oauth-redirect.googleusercontent.com/a/abc',
    'https://oauth-redirect-sandbox.googleusercontent.com/r/abc', 'https://oauth-redirect-test.googleusercontent.com/a/abc']) {
    assert.ok(GOOGLE_REDIRECT_RE.test(u), u);
  }
  for (const u of ['http://oauth-redirect.googleusercontent.com/r/abc', 'https://oauth-redirect.googleusercontent.com/x/abc',
    'https://evil.example/r/abc', 'https://oauth-redirect.googleusercontent.com.evil.example/r/abc']) {
    assert.ok(!GOOGLE_REDIRECT_RE.test(u), u);
  }
});

test('authorize validates every parameter', () => {
  const o = mk();
  const q = (over = {}) => o.authorize(new URL(`http://x/oauth/authorize?${new URLSearchParams({
    response_type: 'code', client_id: 'gemini', redirect_uri: G_URI, code_challenge: CHALLENGE, code_challenge_method: 'S256', ...over })}`));
  assert.equal(q().clientId, 'gemini');
  assert.equal(q({ response_type: 'token' }).error, 'unsupported_response_type');
  assert.equal(q({ client_id: 'nope' }).error, 'invalid_client');
  assert.ok(q({ redirect_uri: 'https://evil.example/r/x' }).error.startsWith('invalid_request'));
  assert.ok(q({ code_challenge_method: 'plain' }).error.startsWith('invalid_request'));
  assert.ok(q({ code_challenge: 'short' }).error.startsWith('invalid_request'));
});

test('authorization_code + PKCE: happy path, replay, mismatch, refresh persistence', () => {
  const o = mk();
  const form = { client_id: 'gemini', secret: 's3cret', redirect_uri: G_URI, code_challenge: CHALLENGE, scope: 'mcp', state: 'xyz' };
  assert.equal(o.consent({ ...form, secret: 'wrong' }), null);
  assert.equal(o.consent({ ...form, redirect_uri: 'https://evil.example/r/x' }), null); // hidden fields are re-validated
  const redirect = new URL(o.consent(form));
  assert.equal(redirect.origin + redirect.pathname, G_URI);
  assert.equal(redirect.searchParams.get('state'), 'xyz');
  const code = redirect.searchParams.get('code');
  const basic = { _basic: Buffer.from('gemini:s3cret').toString('base64') };
  const ex = (over = {}) => o.token({ ...basic, grant_type: 'authorization_code', code, redirect_uri: G_URI, code_verifier: VERIFIER, ...over });
  assert.equal(ex({ code_verifier: crypto.randomBytes(32).toString('base64url') }).body.error, 'invalid_grant');
  assert.equal(ex({ redirect_uri: 'https://oauth-redirect.googleusercontent.com/a/other' }).body.error, 'invalid_grant');
  assert.equal(o.token({ client_id: 'other', client_secret: 'x', grant_type: 'authorization_code', code, redirect_uri: G_URI, code_verifier: VERIFIER }).status, 401);
  const ok = ex();
  assert.equal(ok.status, 200);
  assert.equal(o.verifyAccess(ok.body.refresh_token), null, 'refresh token must not be usable as an access token');
  assert.ok(o.verifyAccess(ok.body.access_token));
  assert.equal(ex().body.error, 'invalid_grant', 'code is single-use');
  const r1 = o.token({ ...basic, grant_type: 'refresh_token', refresh_token: ok.body.refresh_token });
  assert.equal(r1.status, 200);
  assert.equal(r1.body.refresh_token, ok.body.refresh_token, 'persistent linking: same refresh token re-issued');
  assert.ok(o.verifyAccess(r1.body.access_token));
});

test('client_credentials, bad client, unsupported grant', () => {
  const o = mk();
  assert.equal(o.token({ _basic: Buffer.from('gemini:s3cret').toString('base64'), grant_type: 'client_credentials' }).status, 200);
  assert.equal(o.token({ client_id: 'gemini', client_secret: 'nope', grant_type: 'client_credentials' }).status, 401);
  assert.equal(o.token({ _basic: Buffer.from('gemini:s3cret').toString('base64'), grant_type: 'password' }).body.error, 'unsupported_grant_type');
});

test('DCR is off by default; when on, only Google redirect URIs are accepted and the client is persisted', () => {
  assert.equal(mk().register({ redirect_uris: [G_URI] }, () => {}).status, 403);
  let saved = null;
  const o = mk({ allowDcr: true });
  assert.equal(o.register({ redirect_uris: ['https://evil.example/cb'] }, () => {}).status, 400);
  const r = o.register({ redirect_uris: [G_URI], client_name: 'Gemini' }, (c) => { saved = c; });
  assert.equal(r.status, 201);
  assert.match(r.body.client_id, /^dcr-/);
  assert.equal(saved.id, r.body.client_id);
});

test('panel password hashing', async () => {
  const h = await hashPassword('hunter22');
  assert.match(h, /^scrypt\$/);
  assert.ok(await verifyPassword('hunter22', h));
  assert.ok(!(await verifyPassword('hunter23', h)));
  assert.ok(!(await verifyPassword('x', 'garbage')));
});

test('stripOutputSchema removes outputSchema only', () => {
  const msg = { jsonrpc: '2.0', id: 1, result: { tools: [
    { name: 'a', description: 'x', inputSchema: { type: 'object' }, outputSchema: { type: 'object' }, annotations: { readOnlyHint: true } },
    { name: 'b', inputSchema: { type: 'object' } },
  ], nextCursor: null } };
  const out = stripOutputSchema(msg);
  assert.deepEqual(out.result.tools.map((t) => Object.keys(t)), [['name', 'description', 'inputSchema', 'annotations'], ['name', 'inputSchema']]);
  assert.equal(out.result.nextCursor, null);
  assert.equal(msg.result.tools[0].outputSchema.type, 'object', 'input not mutated');
  assert.equal(stripOutputSchema({ jsonrpc: '2.0', id: 1, result: { content: [] } }).result.content.length, 0, 'non-tools messages untouched');
});

test('config: load → update → save round-trips secrets and instances atomically', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gma-'));
  const file = path.join(dir, 'config.yaml');
  load(file);
  update((c) => { c.clients.push({ id: 'x', secret: newSecret(8) }); c.instances.push({ name: 'stitch', url: 'https://stitch.googleapis.com/mcp', auth: { type: 'header', headers: { 'X-Goog-Api-Key': 'abc' } } }); });
  const re = load(file);
  assert.equal(re.clients[0].id, 'x');
  assert.equal(re.instances[0].auth.headers['X-Goog-Api-Key'], 'abc');
  assert.equal(fs.statSync(file).mode & 0o777, 0o600, 'config file must be 0600');
  assert.match(fs.readFileSync(file, 'utf8'), /X-Goog-Api-Key: abc/);
  fs.rmSync(dir, { recursive: true });
});
