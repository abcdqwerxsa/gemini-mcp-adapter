// gemini-mcp-adapter — let Gemini (Google Connected Apps Platform) use any remote MCP
// server. Gemini only accepts "no auth" or "OAuth 2.1 auth-code + PKCE"; the adapter
// presents the latter to Gemini and speaks whatever the upstream needs on the other side.
//
//   /mcp/<name>            MCP endpoint exposed to Gemini (Streamable HTTP, stateless)
//   /oauth/*               authorization server (see oauth.mjs)
//   /.well-known/*         RFC 8414 / RFC 9728 discovery
//   /panel, /api/*         admin UI (cookie session)
//   /healthz
import crypto from 'node:crypto';
import fs from 'node:fs';
import express from 'express';
import { z } from 'zod';
import {
  createMcpExpressApp,
  getOAuthProtectedResourceMetadataUrl,
  hostHeaderValidation,
  mcpAuthMetadataRouter,
  requireBearerAuth,
} from '@modelcontextprotocol/express';
import { OAuthError, OAuthErrorCode } from '@modelcontextprotocol/server';
import { createOAuth, GOOGLE_REDIRECT_RE, jwtVerify, verifyPassword, hashPassword } from './oauth.mjs';
import { forward, probe, resetUpstreamTokens } from './upstream.mjs';
import * as C from './config.mjs';

const ISSUER = 'gemini-mcp-adapter';
const cfg = C.load(process.env.ADAPTER_CONFIG ?? 'config.yaml');
if (!cfg.publicUrl) {
  console.error('config.yaml: publicUrl is required (the HTTPS URL Gemini will connect to)');
  process.exit(1);
}
const PUBLIC = cfg.publicUrl.replace(/\/$/, '');
const hostname = new URL(PUBLIC).hostname;

/** JWT key derived from all client secrets: rotating any secret revokes every token. */
const jwtKey = () => crypto.createHash('sha256').update(C.getConfig().clients.map((c) => c.secret).join('\n')).digest();

// ---- request ring buffer for the panel ----
/** @type {Array<{t: number, inst: string, method: string, status: number, ms: number, client?: string, err?: string}>} */
const reqLog = [];
const LOG_N = 300;
const logReq = (/** @type {any} */ e) => { reqLog.push(e); if (reqLog.length > LOG_N) reqLog.shift(); };

const oauth = createOAuth({
  getClients: () => C.getConfig().clients,
  jwtKey,
  issuer: ISSUER,
  get accessTtl() { return C.getConfig().accessTtl ?? 3600; },
  get refreshTtl() { return C.getConfig().refreshTtl ?? 30 * 86400; },
  get allowDcr() { return !!C.getConfig().allowDcr; },
  redirectAllowed: (uri, client) => (client.redirectUris ?? []).includes(uri) || GOOGLE_REDIRECT_RE.test(uri),
  onRegister: (client) => C.update((c) => { c.clients.push(client); }),
});

const HOST = process.env.HOST ?? cfg.host ?? '127.0.0.1';
const app = createMcpExpressApp({ host: HOST, jsonLimit: '8mb' });
app.set('trust proxy', 1);
app.use(express.urlencoded({ extended: false }));
app.use((req, res, next) => {
  res.on('finish', () => {
    if (req.path !== '/healthz' && !req.path.startsWith('/panel/assets')) {
      console.log(`${req.method} ${req.path} ${res.statusCode} ${res.get('x-rpc-method') ?? ''} ip=${req.ip} ua=${(req.headers['user-agent'] ?? '-').slice(0, 40)}`);
    }
  });
  next();
});
app.get('/healthz', (_req, res) => res.type('text/plain').send('ok'));
app.use(hostHeaderValidation([hostname, 'localhost', '127.0.0.1', '[::1]']));

// ---- discovery ----
app.get('/.well-known/oauth-authorization-server', (_req, res) => {
  res.json({
    issuer: PUBLIC,
    authorization_endpoint: `${PUBLIC}/oauth/authorize`,
    token_endpoint: `${PUBLIC}/oauth/token`,
    ...(cfg.allowDcr ? { registration_endpoint: `${PUBLIC}/oauth/register` } : {}),
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token', 'client_credentials'],
    code_challenge_methods_supported: ['S256'],
    token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
    scopes_supported: ['mcp'],
  });
});
// RFC 9728 path-specific metadata for every instance. Clients probe
// /.well-known/oauth-protected-resource/mcp/<name>; the root form answers for
// the whole adapter so a probe without a path also finds us.
app.get('/.well-known/oauth-protected-resource/mcp/:name', (req, res) => {
  if (!C.getConfig().instances.some((i) => i.name === req.params.name)) return res.status(404).json({ error: 'not_found' });
  res.json({ resource: `${PUBLIC}/mcp/${req.params.name}`, authorization_servers: [PUBLIC], bearer_methods_supported: ['header'] });
});
app.get('/.well-known/oauth-protected-resource', (_req, res) => {
  res.json({ resource: PUBLIC, authorization_servers: [PUBLIC], bearer_methods_supported: ['header'] });
});

// ---- authorization server ----
app.get('/oauth/authorize', (req, res) => {
  const q = oauth.authorize(new URL(req.url, 'http://x'));
  if (q.error) return res.status(400).json(q);
  const esc = (/** @type {string} */ s) => String(s).replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[ch] ?? ch);
  res.type('html').send(`<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>Sign in · MCP adapter</title>
<style>body{font:15px/1.5 system-ui,sans-serif;max-width:28rem;margin:10vh auto;padding:0 1rem;color:#1a1a1a}form{display:grid;gap:.8rem}input{font:inherit;padding:.5rem .6rem;border:1px solid #bbb;border-radius:6px}button{font:inherit;padding:.55rem 1rem;border:0;border-radius:6px;background:#1a73e8;color:#fff;cursor:pointer}p{color:#555}</style>
<h2>Allow <b>${esc(q.clientId)}</b> to use your MCP adapter?</h2>
<p>This signs the MCP client in to every upstream configured on <b>${esc(hostname)}</b>.</p>
<form method=post action=/oauth/consent>
<input type=hidden name=client_id value="${esc(q.clientId)}">
<input type=hidden name=redirect_uri value="${esc(q.redirectUri)}">
<input type=hidden name=code_challenge value="${esc(q.codeChallenge)}">
<input type=hidden name=scope value="${esc(q.scope)}">
<input type=hidden name=state value="${esc(q.state)}">
<label>Client secret<br><input type=password name=secret autocomplete=current-password autofocus required></label>
<button>Allow</button>
</form>`);
});
app.post('/oauth/consent', (req, res, next) => {
  const to = oauth.consent(req.body ?? {});
  if (!to) return res.status(403).type('text/plain').send('wrong client secret, or redirect_uri not allowlisted for this client');
  res.redirect(302, to);
  next();
});
app.post('/oauth/register', express.json({ limit: '64kb' }), (req, res) => {
  const r = oauth.register(req.body, (c) => C.update((cfg) => { cfg.clients.push(c); }));
  res.status(r.status).json(r.body);
});
app.post('/oauth/token', (req, res) => {
  const basic = req.headers.authorization?.startsWith('Basic ') ? req.headers.authorization.slice(6) : '';
  const r = oauth.token({ ...req.body, _basic: basic });
  res.status(r.status).json(r.body);
});

// ---- MCP endpoints: one per instance, behind bearer auth ----
// requireBearerAuth adds WWW-Authenticate: Bearer …, resource_metadata=<per-instance RFC 9728 url>
// so a 401 tells the client where to discover the authorization server.
const bearer = (/** @type {string} */ name) =>
  requireBearerAuth({
    resourceMetadataUrl: getOAuthProtectedResourceMetadataUrl(new URL(`${PUBLIC}/mcp/${name}`)),
    verifier: {
      verifyAccessToken: async (token) => {
        const claims = oauth.verifyAccess(token);
        if (!claims) throw new OAuthError(OAuthErrorCode.InvalidToken, 'unknown, tampered or expired token');
        return { token, clientId: String(claims.sub), scopes: String(claims.scope ?? 'mcp').split(' '), expiresAt: Number(claims.exp) };
      },
    },
  });

const handlerFor = (/** @type {any} */ inst) => async (/** @type {express.Request} */ req, /** @type {express.Response} */ res) => {
  const body = req.body;
  const method = body?.method;
  res.setHeader('x-rpc-method', method ?? '');
  try {
    if (method === 'initialize') {
      const up = await forward(inst, body);
      logReq({ t: Date.now(), inst: inst.name, method: 'initialize', status: up.status, ms: up.ms, client: req.auth?.clientId, err: up.msg?.error?.message });
      if (up.msg?.error) return res.status(502).json(up.msg);
      // present a single stable server identity; keep the negotiated protocol version
      // MCP 2025-11: serverInfo.icons — pass the upstream's own through, or the instance's configured icon
      const icons = inst.icon
        ? [{ src: inst.icon, ...(inst.iconMime ? { mimeType: inst.iconMime } : {}), sizes: ['512x512'] }]
        : up.msg.result?.icons;
      const result = { ...up.msg.result, serverInfo: { name: `adapter/${inst.name}`, version: '0.1.0', ...(icons ? { icons } : {}) } };
      return res.status(200).json({ jsonrpc: '2.0', id: body.id, result });
    }
    if (method === 'ping') return res.status(200).json({ jsonrpc: '2.0', id: body.id, result: {} });
    if (method === 'tools/list') {
      const r = await forward(inst, body);
      logReq({ t: Date.now(), inst: inst.name, method: 'tools/list', status: r.status, ms: r.ms, client: req.auth?.clientId, err: r.msg?.error?.message });
      return res.status(r.msg?.error ? 502 : 200).json(r.msg ?? { jsonrpc: '2.0', id: body.id ?? null, error: { code: -32000, message: 'no upstream response' } });
    }
    if (method === 'tools/call') {
      const r = await forward(inst, body);
      logReq({ t: Date.now(), inst: inst.name, method: `tools/call:${body.params?.name ?? '?'}`, status: r.status, ms: r.ms, client: req.auth?.clientId, err: r.msg?.error?.message });
      if (!r.msg) return res.status(202).end();
      // JSON-RPC-level errors become HTTP 200 + error (per MCP over HTTP); transport failures already carry a synthetic error
      return res.status(200).json(r.msg);
    }
    // notifications and anything else: no reply expected
    if (body?.id === undefined) return res.status(202).end();
    return res.status(200).json({ jsonrpc: '2.0', id: body.id, error: { code: -32601, message: `method not supported through the adapter: ${method}` } });
  } catch (/** @type {any} */ e) {
    logReq({ t: Date.now(), inst: inst.name, method: method ?? '?', status: 504, ms: 0, client: req.auth?.clientId, err: String(e.message ?? e) });
    res.status(504).json({ jsonrpc: '2.0', id: body?.id ?? null, error: { code: -32000, message: `upstream failed: ${String(e.message ?? e)}` } });
  }
};

// One wildcard route serves every instance; the config is consulted per request,
// so instances added/edited/removed in the panel (or by editing config.yaml)
// apply immediately with no re-mount and no restart.
app.post('/mcp/:name', (req, res, next) => {
  const inst = C.getConfig().instances.find((i) => i.name === req.params.name);
  if (!inst) return res.status(404).json({ jsonrpc: '2.0', id: null, error: { code: -32601, message: `no such instance: ${req.params.name}` } });
  bearer(inst.name)(req, res, (err) => (err ? next(err) : handlerFor(inst)(req, res).catch(next)));
});
// Stateless: no GET SSE stream and no session DELETE. HEAD answers like GET-minus-body
// so health probes don't read 405 as "not an MCP endpoint".
const noStream = (/** @type {express.Request} */ req, /** @type {express.Response} */ res) => {
  const inst = C.getConfig().instances.find((i) => i.name === req.params.name);
  if (!inst) return res.status(404).end();
  res.status(405).set('allow', 'POST').end();
};
app.get('/mcp/:name', noStream);
app.head('/mcp/:name', noStream);
app.delete('/mcp/:name', noStream);

// ---- panel ----
app.use('/api', express.json({ limit: '1mb' }));
const SESSION_COOKIE = 'gma_session';
/** @type {Set<string>} */
const sessions = new Set();
const needsPanel = (/** @type {express.Request} */ req, /** @type {express.Response} */ res, /** @type {express.NextFunction} */ next) => {
  const pw = C.getConfig().panel.passwordHash;
  if (!pw) return res.status(503).json({ error: 'panel not set up — POST /api/setup with a password' });
  if (sessions.has(String(req.cookies?.[SESSION_COOKIE] ?? ''))) return next();
  res.status(401).json({ error: 'unauthenticated' });
};
// minimal cookie parsing (no cookie-parser dep)
app.use((req, _res, next) => {
  req.cookies = Object.fromEntries((req.headers.cookie ?? '').split(';').map((s) => s.trim().split('=').map(decodeURIComponent)).filter((p) => p.length === 2));
  next();
});
app.post('/api/setup', async (req, res) => {
  if (C.getConfig().panel.passwordHash) return res.status(409).json({ error: 'panel already set up; use /api/login' });
  const pw = String(req.body?.password ?? '');
  if (pw.length < 8) return res.status(400).json({ error: 'password must be at least 8 characters' });
  const hash = await hashPassword(pw);
  C.update((c) => { c.panel.passwordHash = hash; });
  res.json({ ok: true });
});
app.post('/api/login', async (req, res) => {
  const pw = C.getConfig().panel.passwordHash;
  if (!pw || !(await verifyPassword(String(req.body?.password ?? ''), pw))) return res.status(401).json({ error: 'wrong password' });
  const sid = crypto.randomBytes(24).toString('base64url');
  sessions.add(sid);
  res.cookie(SESSION_COOKIE, sid, { httpOnly: true, sameSite: 'lax', secure: PUBLIC.startsWith('https://'), maxAge: 12 * 3600_000 });
  res.json({ ok: true });
});
app.post('/api/logout', (req, res) => { sessions.delete(String(req.cookies?.[SESSION_COOKIE] ?? '')); res.clearCookie(SESSION_COOKIE); res.json({ ok: true }); });
app.get('/api/me', needsPanel, (_req, res) => res.json({ ok: true, publicUrl: PUBLIC }));

const redact = (/** @type {string} */ s) => (s ? `${s.slice(0, 4)}…${s.slice(-2)}` : '');
const instanceOut = (/** @type {any} */ i) => ({
  name: i.name, url: i.url, authType: i.auth?.type ?? 'none', stripOutputSchema: i.stripOutputSchema !== false,
  headerKeys: Object.keys(i.auth?.headers ?? i.headers ?? {}), paramKeys: Object.keys(i.auth?.params ?? {}),
  hasSecret: ['header', 'bearer', 'oauth2'].includes(i.auth?.type ?? '') || Object.keys(i.headers ?? {}).length > 0,
  icon: i.icon,
});
app.get('/api/instances', needsPanel, (_req, res) => res.json(C.getConfig().instances.map(instanceOut)));
app.get('/api/instances/:name', needsPanel, (req, res) => {
  const i = C.getConfig().instances.find((x) => x.name === req.params.name);
  if (!i) return res.status(404).json({ error: 'not found' });
  res.json({ ...instanceOut(i), auth: i.auth ? { ...i.auth, token: redact(i.auth.token), clientSecret: redact(i.auth.clientSecret) } : undefined, headers: i.headers ? Object.fromEntries(Object.entries(i.headers).map(([k, v]) => [k, redact(String(v))])) : undefined });
});
const instanceIn = z.object({
  name: z.string().regex(/^[a-z0-9][a-z0-9-]{0,40}$/),
  url: z.string().url(),
  auth: z.discriminatedUnion('type', [
    z.object({ type: z.literal('none') }),
    z.object({ type: z.literal('header'), headers: z.record(z.string(), z.string()) }),
    z.object({ type: z.literal('query'), params: z.record(z.string(), z.string()) }),
    z.object({ type: z.literal('bearer'), token: z.string().optional(), tokenEnv: z.string().optional() }),
    z.object({ type: z.literal('oauth2'), tokenUrl: z.string().url(), clientId: z.string(), clientSecret: z.string().optional(), clientSecretEnv: z.string().optional(), scope: z.string().optional(), clientAuth: z.enum(['basic', 'post']).optional() }),
  ]).optional(),
  headers: z.record(z.string(), z.string()).optional(),
  stripOutputSchema: z.boolean().optional(),
  timeoutMs: z.number().int().min(1000).max(600_000).optional(),
  icon: z.string().url().optional(),
});
app.post('/api/instances', needsPanel, (req, res) => {
  const parsed = instanceIn.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.issues.map((i) => i.message).join('; ') });
  if (C.getConfig().instances.some((i) => i.name === parsed.data.name)) return res.status(409).json({ error: 'name already exists' });
  C.update((c) => { c.instances.push(parsed.data); });
  resetUpstreamTokens();
  res.status(201).json(instanceOut(parsed.data));
});
app.put('/api/instances/:name', needsPanel, (req, res) => {
  const parsed = instanceIn.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.issues.map((i) => i.message).join('; ') });
  const existing = C.getConfig().instances.find((i) => i.name === req.params.name);
  if (!existing) return res.status(404).json({ error: 'not found' });
  // editing keeps the route (name is the key); a renamed instance must be deleted + re-added
  if (parsed.data.name !== req.params.name) return res.status(400).json({ error: 'rename is not supported; delete and re-add' });
  C.update((c) => { c.instances = c.instances.map((i) => (i.name === req.params.name ? parsed.data : i)); });
  resetUpstreamTokens();
  res.json(instanceOut(parsed.data));
});
app.delete('/api/instances/:name', needsPanel, (req, res) => {
  C.update((c) => { c.instances = c.instances.filter((i) => i.name !== req.params.name); });
  // routes for a deleted name stay mounted but resolve 404 on the next request via the lookup below
  res.json({ ok: true });
});
app.post('/api/instances/:name/probe', needsPanel, async (req, res) => {
  const i = C.getConfig().instances.find((x) => x.name === req.params.name);
  if (!i) return res.status(404).json({ error: 'not found' });
  try { res.json(await probe(i)); } catch (/** @type {any} */ e) { res.status(502).json({ ok: false, error: String(e.message ?? e) }); }
});

app.get('/api/clients', needsPanel, (_req, res) => res.json(C.getConfig().clients.map((c) => ({ id: c.id, name: c.name, redirectUris: c.redirectUris }))));
app.post('/api/clients', needsPanel, (req, res) => {
  const id = String(req.body?.id ?? '').trim();
  if (!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,40}$/.test(id)) return res.status(400).json({ error: 'id must be 1-41 chars [A-Za-z0-9_.-]' });
  if (C.getConfig().clients.some((c) => c.id === id)) return res.status(409).json({ error: 'client exists' });
  const secret = C.newSecret();
  C.update((c) => { c.clients.push({ id, secret, name: String(req.body?.name ?? id) }); });
  res.status(201).json({ id, secret });
});
// Panel is already authenticated; let it reveal a client secret on demand (the
// Gemini dialog and the consent page both need it, and "shown once" was a UX trap).
app.get('/api/clients/:id/secret', needsPanel, (req, res) => {
  const c = C.getConfig().clients.find((x) => x.id === req.params.id);
  if (!c) return res.status(404).json({ error: 'not found' });
  res.json({ id: c.id, secret: c.secret });
});
app.post('/api/clients/:id/rotate', needsPanel, (req, res) => {
  if (!C.getConfig().clients.some((c) => c.id === req.params.id)) return res.status(404).json({ error: 'not found' });
  const secret = C.newSecret();
  C.update((c) => { const cl = c.clients.find((x) => x.id === req.params.id); if (cl) cl.secret = secret; });
  res.json({ id: req.params.id, secret });
});
app.delete('/api/clients/:id', needsPanel, (req, res) => {
  C.update((c) => { c.clients = c.clients.filter((x) => x.id !== req.params.id); });
  res.json({ ok: true });
});
app.get('/api/log', needsPanel, (_req, res) => res.json(reqLog.slice(-100).reverse()));
app.get('/api/meta', needsPanel, (_req, res) => res.json({ publicUrl: PUBLIC, allowDcr: !!C.getConfig().allowDcr, instances: C.getConfig().instances.length, clients: C.getConfig().clients.length }));
app.get('/panel', (_req, res) => res.type('html').send(fs.readFileSync(new URL('./panel.html', import.meta.url))));
app.get('/', (_req, res) => res.redirect('/panel'));


// no stack traces to clients
app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(err.status ?? 500).json({ error: err.expose ? err.message : 'internal error' });
});
const port = Number(process.env.PORT) || cfg.port || 3334;
app.listen(port, HOST, () => {
  console.log(`gemini-mcp-adapter listening on http://${HOST}:${port}  public=${PUBLIC}  instances=${C.getConfig().instances.length}`);
});
