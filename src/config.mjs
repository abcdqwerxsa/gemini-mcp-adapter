// Config: one YAML file, hot-reloaded on every save, written atomically.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import YAML from 'yaml';

/** @typedef {import('./upstream.mjs').Instance} Instance */
/** @typedef {{id: string, secret: string, name?: string, redirectUris?: string[]}} Client */
/**
 * @typedef {object} Config
 * @property {string} publicUrl
 * @property {string} [host]
 * @property {number} [port]
 * @property {{passwordHash?: string}} panel
 * @property {Client[]} clients
 * @property {Instance[]} instances
 * @property {boolean} [allowDcr]
 * @property {number} [accessTtl]
 * @property {number} [refreshTtl]
 */

/** @type {Config} */
let cfg;
/** @type {string} */
let file;

const DEFAULTS = /** @type {Config} */ ({
  publicUrl: 'http://127.0.0.1:3334',
  host: '127.0.0.1',
  port: 3334,
  panel: {},
  clients: [],
  instances: [],
  allowDcr: false,
  accessTtl: 3600,
  refreshTtl: 30 * 86400,
});

/** @returns {Config} */
export function getConfig() {
  return cfg;
}

export function configPath() {
  return file;
}

export function load(/** @type {string} */ p) {
  file = path.resolve(p);
  if (!fs.existsSync(file)) {
    fs.writeFileSync(file, YAML.stringify({ publicUrl: DEFAULTS.publicUrl, panel: {}, clients: [], instances: [] }), { mode: 0o600 });
  }
  cfg = { ...DEFAULTS, ...YAML.parse(fs.readFileSync(file, 'utf8')) };
  cfg.instances ??= [];
  cfg.clients ??= [];
  cfg.panel ??= {};
  fs.chmodSync(file, 0o600);
  return cfg;
}

/** Persist the current in-memory config atomically (tmp + rename). */
export function save() {
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, YAML.stringify(cfg), { mode: 0o600 });
  fs.renameSync(tmp, file);
  return cfg;
}

/**
 * Apply a mutation to the config and persist it. The mutator receives the live object.
 * @param {(c: Config) => void} fn
 */
export function update(fn) {
  fn(cfg);
  save();
  return cfg;
}

export const newSecret = (/** @type {number} */ bytes = 32) => crypto.randomBytes(bytes).toString('hex');
