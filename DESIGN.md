# gemini-mcp-adapter — design notes

## What it is
A reverse proxy + OAuth 2.1 authorization server that lets **any** remote MCP
server be consumed from **Gemini (Google Connected Apps Platform)**, which only
accepts two auth modes: none, or OAuth 2.1 authorization-code + PKCE.

```
Gemini ──OAuth2.1+PKCE──▶ adapter ──(inject creds)──▶ upstream MCP(s)
                           /mcp/<name>                 none | header | query | bearer | oauth2
                           /panel                       (admin UI, cookie session)
```

## Upstream transports (how adapter talks to the MCP server)
- `streamable-http` (default): POST JSON-RPC to `url`, `Accept: application/json, text/event-stream`.
  Pass through `Mcp-Session-Id` if the upstream sets one. Return JSON or SSE (normalized to SSE for Gemini).
- Legacy `sse` transport: NOT supported in v1 (rare now; Gemini itself rejects SSE-only servers).

## Upstream auth (`auth` block in config)
| type         | fields                              | adapter behaviour |
|--------------|-------------------------------------|------------------|
| `none`       | —                                   | pass through |
| `header`     | `headers: {K: V}`                   | static headers on every upstream call |
| `query`      | `params: {k: v}`                    | static query params |
| `bearer`     | `token: "...`" or `tokenEnv: NAME`  | `Authorization: Bearer …` |
| `oauth2`     | `tokenUrl, clientId, clientSecret, scope?` | client_credentials; token cached until expiry |

## Gemini-facing auth (what the adapter exposes)
- Own OAuth 2.1 AS at `/oauth/*`: authorization_code + PKCE S256, refresh_token (persistent: same
  token re-issued, never rotated — per Google's guide), client_credentials for scripts.
- Discovery: RFC 8414 at `/.well-known/oauth-authorization-server`, RFC 9728 per instance at
  `/.well-known/oauth-protected-resource/mcp/<name>`.
- Clients: `{id, secret, name}` rows in config, managed from the panel. Consent page asks for the
  client secret (no user DB). DCR supported (`/oauth/register`) but off by default.
- Redirect allowlist: `https://oauth-redirect.googleusercontent.com/...` (prod/sandbox/test).

## Tools passthrough + token hygiene
- `tools/list` is forwarded and **`outputSchema` is stripped** (Stitch: 417 KB → ~8 KB). Gemini
  never uses outputSchema to form calls; it only bloats context. Optional per instance.
- `tools/call` results pass through untouched (text/image/resource content preserved).
- `initialize` is answered by the adapter (serverInfo = adapter name + upstream name) so Gemini
  sees one consistent server; protocol version negotiated from upstream.

## Config
Single YAML at `ADAPTER_CONFIG` (default `./config.yaml`), hot-reloaded on every panel save:
```yaml
publicUrl: https://mcp.nilpo.org
clients: [{id: gemini, secret: …, name: "My Gemini"}]
instances:
  - name: stitch
    url: https://stitch.googleapis.com/mcp
    auth: {type: header, headers: {X-Goog-Api-Key: …}}
    stripOutputSchema: true
```
Secrets stay in this file (chmod 600). Panel edits write atomically (tmp + rename).

## Panel
Single-page admin UI at `/panel` (cookie session, password = `panel.passwordHash`).
- list instances: name, upstream, auth type, tool count, last probe status/latency, errors
- add / edit / delete instance (form; secret fields masked)
- add / revoke Gemini clients; rotate secret (one click)
- probe an instance: forward `tools/list`, show tool names + payload size before/after strip
- live request log (last N proxied calls: method, status, ms)
- copy-paste block for Gemini dialog (URL / client id / secret)
