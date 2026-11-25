// OAuth 2.1 authorization server for the adapter's Gemini-facing side.
// authorization_code + PKCE(S256), refresh_token (persistent: the same token is re-issued),
// client_credentials for scripts, optional RFC 7591 dynamic registration.
// No user database: the consent page asks for the client's own secret.
import crypto from 'node:crypto';
import { promisify } from 'node:util';
const scrypt = promisify(crypto.scrypt);

export const GOOGLE_REDIRECT_RE =
  /^https:\/\/oauth-redirect(?:-sandbox|-test)?\.googleusercontent\.com\/[ra]\/.+$/;

const b64u = (/** @type {string | Buffer} */ d) => Buffer.from(d).toString('base64url');
const rnd = () => crypto.randomBytes(32).toString('base64url');

/** Timing-safe compare; a length leak on hash-like ids is acceptable. */
export function safeEqual(/** @type {string} */ a, /** @type {string} */ b) {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

const sign = (/** @type {Buffer} */ key, /** @type {string} */ data) =>
  crypto.createHmac('sha256', key).update(data).digest(); // raw bytes; b64u() at the call site

/**
 * Minimal HS256 JWT (typ separates access from refresh tokens).
 * @param {Record<string, unknown>} claims
 * @param {Buffer} key
 */
export function jwt(claims, key) {
  const h = b64u(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const p = b64u(JSON.stringify(claims));
  return `${h}.${p}.${b64u(sign(key, `${h}.${p}`))}`;
}

/**
 * Verify an HS256 JWT from this AS. Returns claims or null.
 * @param {string} token
 * @param {Buffer} key
 * @param {string} iss
 */
export function jwtVerify(token, key, iss) {
  const [h, p, s] = String(token).split('.');
  if (!h || !p || !s) return null;
  const expect = sign(key, `${h}.${p}`);
  const got = Buffer.from(s, 'base64url');
  if (got.length !== expect.length || !crypto.timingSafeEqual(got, expect)) return null;
  try {
    const head = JSON.parse(Buffer.from(h, 'base64url').toString());
    const c = JSON.parse(Buffer.from(p, 'base64url').toString());
    if (head.alg !== 'HS256' || c.iss !== iss || typeof c.exp !== 'number') return null;
    if (c.exp <= Date.now() / 1000) return null;
    return c;
  } catch {
    return null;
  }
}

/**
 * @typedef {{id: string, secret: string, name?: string, redirectUris?: string[]}} Client
 */

/**
 * @param {{getClients: () => Client[], jwtKey: () => Buffer, issuer: string,
 *          accessTtl: number, refreshTtl: number, allowDcr: boolean,
 *          redirectAllowed: (uri: string, client: Client) => boolean}} cfg
 *   All getters are functions so config hot-reloads are honored.
 */
export function createOAuth(cfg) {
  /** @type {Map<string, {clientId: string, redirectUri: string, codeChallenge: string, scope: string, exp: number}>} */
  const codes = new Map();
  const now = () => Math.floor(Date.now() / 1000);

  const issue = (/** @type {string} */ sub, /** @type {string} */ scope, /** @type {string | undefined} */ jti) => {
    const t = now();
    const refresh = jti ?? `${sub}.${rnd()}`;
    return {
      access_token: jwt({ iss: cfg.issuer, sub, iat: t, exp: t + cfg.accessTtl, scope }, cfg.jwtKey()),
      token_type: 'Bearer',
      expires_in: cfg.accessTtl,
      // persistent linking: same jti every time, lifetime extended server-side by refreshTtl
      refresh_token: jwt({ iss: cfg.issuer, sub, jti: refresh, iat: t, exp: t + cfg.refreshTtl, scope, typ: 'refresh' }, cfg.jwtKey()),
      scope,
    };
  };

  const validChallenge = (/** @type {string} */ c) => /^[A-Za-z0-9_-]{43,128}$/.test(c);

  return {
    /** Validate an authorization request. Returns params or {error, error_description}. */
    authorize(/** @type {URL} */ url) {
      const p = url.searchParams;
      const q = {
        clientId: p.get('client_id') ?? '',
        redirectUri: p.get('redirect_uri') ?? '',
        codeChallenge: p.get('code_challenge') ?? '',
        method: p.get('code_challenge_method') ?? '',
        scope: p.get('scope') ?? 'mcp',
        state: p.get('state') ?? '',
      };
      const err = (error, error_description) => ({ error, error_description });
      if (p.get('response_type') !== 'code') return err('unsupported_response_type', 'only "code" is supported');
      const client = cfg.getClients().find((c) => c.id === q.clientId);
      if (!client) return err('invalid_client', 'unknown client_id');
      if (!cfg.redirectAllowed(q.redirectUri, client)) return err('invalid_request', 'redirect_uri is not allowlisted');
      if (q.method !== 'S256') return err('invalid_request', 'code_challenge_method must be S256');
      if (!validChallenge(q.codeChallenge)) return err('invalid_request', 'bad code_challenge');
      return q;
    },

    /**
     * Validate the consent form and mint a one-time code (60 s). Hidden fields are
     * client-controlled, so everything is re-validated here.
     * @returns {string | null} redirect URL
     */
    consent(/** @type {Record<string, string>} */ f) {
      const client = cfg.getClients().find((c) => c.id === f.client_id);
      if (!client || !f.secret || !safeEqual(f.secret, client.secret)) return null;
      if (!cfg.redirectAllowed(f.redirect_uri, client)) return null;
      if (!validChallenge(f.code_challenge)) return null;
      const code = rnd();
      codes.set(code, { clientId: f.client_id, redirectUri: f.redirect_uri, codeChallenge: f.code_challenge, scope: f.scope || 'mcp', exp: now() + 60 });
      // prune expired codes opportunistically
      for (const [k, v] of codes) if (v.exp < now()) codes.delete(k);
      const to = new URL(f.redirect_uri);
      to.searchParams.set('code', code);
      to.searchParams.set('state', f.state ?? '');
      return to.toString();
    },

    /**
     * RFC 7591 dynamic registration. Only when enabled; registered clients get the
     * default (Google) redirect allowlist and are written back via cfg.onRegister.
     * @param {any} body
     */
    register(body, /** @type {(c: Client) => void} */ onRegister) {
      if (!cfg.allowDcr) return { status: 403, body: { error: 'access_denied', error_description: 'dynamic registration is disabled' } };
      const uris = Array.isArray(body?.redirect_uris) ? body.redirect_uris.map(String) : [];
      if (!uris.length || !uris.every((/** @type {string} */ u) => GOOGLE_REDIRECT_RE.test(u))) {
        return { status: 400, body: { error: 'invalid_redirect_uri', error_description: 'only Google Connected Apps redirect URIs are accepted' } };
      }
      const client = { id: `dcr-${rnd().slice(0, 12)}`, secret: rnd(), name: String(body.client_name ?? 'DCR client'), redirectUris: uris };
      onRegister(client);
      return {
        status: 201,
        body: {
          client_id: client.id, client_secret: client.secret, client_name: client.name,
          redirect_uris: uris, grant_types: ['authorization_code', 'refresh_token'],
          response_types: ['code'], token_endpoint_auth_method: 'client_secret_basic',
        },
      };
    },

    /** POST /oauth/token — all grants. `f._basic` is the decoded Basic credential if present. */
    token(/** @type {Record<string, string>} */ f) {
      const bad = (error, error_description, status = 400) => ({ status, body: { error, error_description } });
      let id = '';
      let secret = '';
      if (f._basic) {
        const dec = Buffer.from(f._basic, 'base64').toString('utf8').split(':');
        id = decodeURIComponent(dec[0] ?? '');
        secret = decodeURIComponent(dec.slice(1).join(':'));
      }
      id ||= f.client_id ?? '';
      secret ||= f.client_secret ?? '';
      const client = cfg.getClients().find((c) => c.id === id);
      if (!client || !secret || !safeEqual(secret, client.secret)) return bad('invalid_client', 'unknown client or bad secret', 401);
      const grant = f.grant_type ?? '';
      if (grant === 'client_credentials') return { status: 200, body: issue(id, f.scope ?? 'mcp', undefined) };

      if (grant === 'refresh_token') {
        const c = jwtVerify(f.refresh_token ?? '', cfg.jwtKey(), cfg.issuer);
        if (!c || c.typ !== 'refresh' || c.sub !== id) return bad('invalid_grant', 'bad refresh token');
        return { status: 200, body: issue(id, c.scope ?? 'mcp', /** @type {string} */ (c.jti)) };
      }

      if (grant === 'authorization_code') {
        const rec = codes.get(f.code ?? '');
        if (!rec || rec.exp < now() || rec.clientId !== id) return bad('invalid_grant', 'unknown, expired or foreign code');
        if (rec.redirectUri !== (f.redirect_uri ?? '')) return bad('invalid_grant', 'redirect_uri mismatch');
        const verifier = f.code_verifier ?? '';
        if (!/^[A-Za-z0-9_-]{43,128}$/.test(verifier) ||
            crypto.createHash('sha256').update(verifier).digest('base64url') !== rec.codeChallenge) {
          return bad('invalid_grant', 'PKCE verification failed');
        }
        codes.delete(f.code);
        return { status: 200, body: issue(id, rec.scope, undefined) };
      }
      return bad('unsupported_grant_type', 'supported: authorization_code, refresh_token, client_credentials');
    },

    /** Validate a bearer access token on the MCP route. Returns claims or null. */
    verifyAccess(/** @type {string} */ token) {
      const c = jwtVerify(token, cfg.jwtKey(), cfg.issuer);
      return c && c.typ !== 'refresh' ? c : null;
    },
  };
}

/** Password hashing for the panel (scrypt; no deps). */
export async function hashPassword(/** @type {string} */ pw) {
  const salt = crypto.randomBytes(16);
  const hash = /** @type {Buffer} */ (await scrypt(pw, salt, 32));
  return `scrypt$${salt.toString('base64url')}$${hash.toString('base64url')}`;
}
export async function verifyPassword(/** @type {string} */ pw, /** @type {string} */ stored) {
  const [alg, salt, hash] = stored.split('$');
  if (alg !== 'scrypt' || !salt || !hash) return false;
  const got = /** @type {Buffer} */ (await scrypt(pw, Buffer.from(salt, 'base64url'), 32));
  const want = Buffer.from(hash, 'base64url');
  return got.length === want.length && crypto.timingSafeEqual(got, want);
}
