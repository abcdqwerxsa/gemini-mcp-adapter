// Upstream side of the adapter: talk to any remote MCP server over Streamable HTTP,
// injecting whatever credentials its config asks for. JSON-RPC is forwarded verbatim
// (we never interpret tool semantics); only tools/list gets outputSchema stripped
// (token hygiene) and initialize is answered by the adapter itself.
/** @typedef {{name: string, url: string, auth?: object, stripOutputSchema?: boolean, headers?: Record<string,string>, timeoutMs?: number}} Instance */

/**
 * Resolve the upstream credentials for one call. Returns headers + query to add.
 * Caches oauth2 client_credentials tokens until shortly before expiry.
 * @param {Instance} inst
 */
export async function upstreamAuth(inst) {
  /** @type {Record<string,string>} */
  const headers = {};
  /** @type {Record<string,string>} */
  const query = {};
  const a = inst.auth ?? { type: 'none' };
  for (const [k, v] of Object.entries(inst.headers ?? {})) headers[k] = String(v);
  switch (a.type) {
    case 'none':
      break;
    case 'header':
      for (const [k, v] of Object.entries(a.headers ?? {})) headers[k] = String(v);
      break;
    case 'query':
      for (const [k, v] of Object.entries(a.params ?? {})) query[k] = String(v);
      break;
    case 'bearer':
      headers.Authorization = `Bearer ${a.tokenEnv ? process.env[a.tokenEnv] ?? '' : a.token ?? ''}`;
      break;
    case 'oauth2': {
      const cached = tokenCache.get(inst.name);
      if (cached && cached.exp - 30 > Date.now() / 1000) {
        headers.Authorization = `Bearer ${cached.token}`;
        break;
      }
      const body = new URLSearchParams({ grant_type: 'client_credentials' });
      if (a.scope) body.set('scope', a.scope);
      const clientSecret = a.clientSecret ?? process.env[a.clientSecretEnv ?? ''] ?? '';
      if (a.clientAuth === 'post') {
        body.set('client_id', a.clientId);
        body.set('client_secret', clientSecret);
      }
      const res = await fetch(a.tokenUrl, {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          ...(a.clientAuth === 'post' ? {} : { Authorization: `Basic ${Buffer.from(`${a.clientId}:${clientSecret}`).toString('base64')}` }),
        },
        body,
        signal: AbortSignal.timeout(15_000),
      });
      const json = /** @type {any} */ (await res.json().catch(() => ({})));
      if (!res.ok || !json.access_token) {
        throw new Error(`oauth2 token fetch failed: HTTP ${res.status} ${json.error_description ?? json.error ?? ''}`);
      }
      const exp = Date.now() / 1000 + (Number(json.expires_in) || 3600);
      tokenCache.set(inst.name, { token: json.access_token, exp });
      headers.Authorization = `Bearer ${json.access_token}`;
      break;
    }
    default:
      throw new Error(`unknown auth type "${a.type}"`);
  }
  return { headers, query };
}

/** @type {Map<string, {token: string, exp: number}>} */
const tokenCache = new Map();
/** Drop cached upstream tokens (after config change or panel "reset"). */
export function resetUpstreamTokens() {
  tokenCache.clear();
}

/**
 * Strip outputSchema (and $defs it pulls in) from every tool in a tools/list result.
 * Gemini never uses outputSchema to form calls; it only bloats context.
 * @param {any} msg
 */
export function stripOutputSchema(msg) {
  const tools = msg?.result?.tools;
  if (!Array.isArray(tools)) return msg;
  return { ...msg, result: { ...msg.result, tools: tools.map(({ outputSchema, ...rest }) => rest) } };
}

/** Parse one JSON-RPC message out of an SSE or JSON response body. */
async function readRpcMessage(/** @type {Response} */ res) {
  const text = await res.text();
  const ct = res.headers.get('content-type') ?? '';
  if (ct.includes('text/event-stream')) {
    // take the last `data:` line that parses as JSON-RPC with a result or error
    for (const line of text.split(/\r?\n/).reverse()) {
      if (!line.startsWith('data:')) continue;
      try {
        const m = JSON.parse(line.slice(5).trim());
        if (m && (m.result !== undefined || m.error !== undefined || m.method)) return m;
      } catch { /* keep scanning */ }
    }
    throw new Error(`upstream SSE carried no JSON-RPC message (${text.slice(0, 120)})`);
  }
  return JSON.parse(text);
}

/**
 * Forward one JSON-RPC request to the upstream and return its message.
 * @param {Instance} inst
 * @param {any} msg
 * @param {{sessionId?: string}} opts
 * @param {import('node:http').IncomingMessage} [req]  (for client hints; optional)
 */
export async function forward(inst, msg, opts = {}, req) {
  const url = new URL(inst.url);
  const { headers, query } = await upstreamAuth(inst);
  for (const [k, v] of Object.entries(query)) url.searchParams.set(k, v);
  const hdrs = {
    'content-type': 'application/json',
    accept: 'application/json, text/event-stream',
    'user-agent': 'gemini-mcp-adapter/0.1',
    ...headers,
  };
  if (opts.sessionId) hdrs['mcp-session-id'] = opts.sessionId;
  if (req?.headers['mcp-protocol-version']) hdrs['mcp-protocol-version'] = String(req.headers['mcp-protocol-version']);
  const t0 = Date.now();
  const res = await fetch(url, {
    method: 'POST',
    headers: hdrs,
    body: JSON.stringify(msg),
    signal: AbortSignal.timeout(inst.timeoutMs ?? 90_000),
  });
  const sessionId = res.headers.get('mcp-session-id') ?? undefined;
  if (!res.ok && res.status !== 202) {
    const body = (await res.text()).slice(0, 500);
    // surface upstream auth failures as JSON-RPC errors so clients show something useful
    return {
      msg: { jsonrpc: '2.0', id: msg.id ?? null, error: { code: -32000, message: `upstream HTTP ${res.status}: ${body}` } },
      sessionId, ms: Date.now() - t0, status: res.status,
    };
  }
  if (res.status === 202) return { msg: null, sessionId, ms: Date.now() - t0, status: 202 };
  let out = await readRpcMessage(res);
  if (msg.method === 'tools/list' && inst.stripOutputSchema !== false) out = stripOutputSchema(out);
  return { msg: out, sessionId, ms: Date.now() - t0, status: res.status };
}

/** Ask the upstream what it is (initialize) — used by the panel's probe. */
export async function probe(inst) {
  const init = {
    jsonrpc: '2.0', id: 1, method: 'initialize',
    params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'gemini-mcp-adapter', version: '0.1.0' } },
  };
  const a = await forward(inst, init);
  if (!a.msg || a.msg.error) return { ok: false, error: a.msg?.error?.message ?? 'no response', ms: a.ms };
  // notifications/initialized is a notification (no id); upstream returns 202
  await forward(inst, { jsonrpc: '2.0', method: 'notifications/initialized' }, { sessionId: a.sessionId }).catch(() => {});
  const b = await forward(inst, { jsonrpc: '2.0', id: 2, method: 'tools/list' }, { sessionId: a.sessionId });
  const tools = b.msg?.result?.tools ?? [];
  // measure how much outputSchema stripping saved on this upstream
  const raw = await forward({ ...inst, stripOutputSchema: false }, { jsonrpc: '2.0', id: 3, method: 'tools/list' }, { sessionId: a.sessionId }).catch(() => null);
  const rawBytes = raw?.msg ? JSON.stringify(raw.msg).length : null;
  return {
    ok: !b.msg?.error,
    error: b.msg?.error?.message,
    ms: a.ms + b.ms,
    serverInfo: a.msg.result?.serverInfo,
    protocolVersion: a.msg.result?.protocolVersion,
    instructions: a.msg.result?.instructions,
    tools: tools.map((/** @type {any} */ t) => ({ name: t.name, description: t.description, readOnly: t.annotations?.readOnlyHint })),
    listBytes: JSON.stringify(b.msg ?? {}).length,
    rawListBytes: rawBytes,
  };
}


