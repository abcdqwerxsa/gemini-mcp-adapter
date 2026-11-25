# gemini-mcp-adapter

Let **Gemini** (Google Connected Apps Platform / gemini.google.com/devmode) use **any** remote MCP server.

Gemini only accepts two auth modes for custom MCP servers — none, or OAuth 2.1 authorization-code + PKCE.
The adapter presents OAuth 2.1 to Gemini and speaks whatever the upstream needs on the other side.

```
Gemini ──OAuth 2.1 + PKCE──▶ adapter ──(inject creds)──▶ upstream MCP(s)
                              /mcp/<name>                none · header · query · bearer · oauth2
                              /panel                     admin UI (instances, clients, probe, log)
```

## Features

- **One process, N upstreams**: each instance is mounted at `/mcp/<name>`; JSON-RPC is forwarded verbatim (no tool-semantics rewriting).
- **Upstream auth**: `none` / `header` (API keys) / `query` / `bearer` / `oauth2` (client_credentials, tokens cached).
- **Gemini-facing OAuth 2.1 AS**: authorization_code + PKCE S256, refresh_token with *persistent linking* (same token re-issued), client_credentials for scripts, optional RFC 7591 DCR, RFC 8414 + per-instance RFC 9728 discovery, Google redirect allowlist.
- **Token hygiene**: `outputSchema` is stripped from `tools/list` (Stitch: 396 KB → 52 KB). Per-instance switch.
- **Admin panel** at `/panel`: add/edit/delete instances, probe upstream (tools, latency, payload before/after), manage Gemini clients (create / rotate secret / revoke), live request log, copy-paste block for the Gemini dialog. Cookie session; password set on first visit.
- Config is one YAML file (`ADAPTER_CONFIG`), chmod 600, written atomically on every panel change — no restarts.

## Run

```bash
npm ci
ADAPTER_CONFIG=./config.yaml npm start      # default 127.0.0.1:3334
```

Minimal `config.yaml` (everything else can be done from the panel):

```yaml
publicUrl: https://mcp.example.com
panel: {}
clients: []
instances: []
```

Behind a TLS proxy (Cloudflare / Caddy / traefik). Set `publicUrl` to the public HTTPS URL; Host-header validation uses its hostname.

### Connect Gemini

1. Panel → *Instances* → add the upstream (URL + auth) → **检测** until it shows tools.
2. Panel → *Gemini Clients* → create a client, copy the secret (shown once).
3. Gemini → Settings → Connected apps (or `gemini.google.com/devmode`) → *Connect to an MCP server*:
   - MCP Server URL: `https://<publicUrl>/mcp/<name>`
   - Client ID / Client secret: from step 2
   - *Copy redirect URI*: nothing to configure — `https://oauth-redirect{,-sandbox,-test}.googleusercontent.com/{r,a}/*` is allowlisted.
4. The consent page asks for the same client secret.

### Deploy (k3s, oci-arm2)

See `deploy/k8s.yaml`: source on the host at `/opt/gemini-mcp-adapter/app` (~30 KB, no image build), `config.yaml` at `/opt/gemini-mcp-adapter/data`, initContainer runs `npm ci`.

```bash
tar czf src.tgz package.json package-lock.json src
scp src.tgz oci-arm2:/tmp/ && ssh oci-arm2 'sudo tar xzf /tmp/src.tgz -C /opt/gemini-mcp-adapter/app && sudo chown -R 1000:1000 /opt/gemini-mcp-adapter'
ssh oci-arm2 'sudo kubectl apply -f ~/gemini-mcp-adapter/k8s.yaml && sudo kubectl rollout restart deploy/gemini-mcp-adapter'
```

## Limits (v1)

- Upstreams that require **per-user OAuth** (Notion, GitHub user tokens…) are not supported: every Gemini user shares the credentials in the instance config. Consent page says so.
- Legacy SSE-only upstreams are not supported (Gemini itself rejects them).
- Sessions/cookies are in-memory; a restart logs the panel out and drops in-flight codes. Tokens survive (stateless JWT).
- Deleting an instance leaves its route mounted; it answers 404 until restart.

## Tests

`npm test` — JWT/PKCE/refresh/DCR/allowlist/password hashing/outputSchema stripping/config round-trip (9).
