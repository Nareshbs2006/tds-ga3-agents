// Node HTTP server for Render (or local dev). Uses Postgres when DATABASE_URL is set,
// otherwise a JSON file on disk.
import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { createApp } from "./src/app.js";

async function makeStore() {
  if (process.env.DATABASE_URL) {
    const { default: pg } = await import("pg");
    const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.PGSSL === "0" ? false : { rejectUnauthorized: false }, max: 5 });
    await pool.query("CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v JSONB NOT NULL)");
    const cache = new Map();
    return {
      async get(k) {
        if (cache.has(k)) return structuredClone(cache.get(k));
        const r = await pool.query("SELECT v FROM kv WHERE k=$1", [k]);
        if (!r.rows.length) return undefined;
        cache.set(k, r.rows[0].v);
        return structuredClone(r.rows[0].v);
      },
      async put(k, v) {
        await pool.query("INSERT INTO kv (k, v) VALUES ($1, $2) ON CONFLICT (k) DO UPDATE SET v = EXCLUDED.v", [k, JSON.stringify(v)]);
        cache.set(k, structuredClone(v));
      },
    };
  }
  const file = process.env.STORE_FILE || "./data/store.json";
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const data = fs.existsSync(file) ? JSON.parse(fs.readFileSync(file, "utf8")) : {};
  let timer = null;
  const flush = () => fs.writeFileSync(file, JSON.stringify(data));
  return {
    async get(k) {
      return k in data ? structuredClone(data[k]) : undefined;
    },
    async put(k, v) {
      data[k] = structuredClone(v);
      clearTimeout(timer);
      timer = setTimeout(flush, 50);
    },
  };
}

const store = await makeStore();
const handler = createApp(store, process.env);
const port = Number(process.env.PORT || 8787);

http
  .createServer(async (req, res) => {
    const chunks = [];
    for await (const c of req) chunks.push(c);
    const proto = req.headers["x-forwarded-proto"] || "http";
    const url = `${proto}://${req.headers.host}${req.url}`;
    const body = chunks.length ? Buffer.concat(chunks) : undefined;
    const request = new Request(url, { method: req.method, headers: req.headers, body: ["GET", "HEAD"].includes(req.method) ? undefined : body });
    const r = await handler(request);
    const buf = Buffer.from(await r.arrayBuffer());
    res.writeHead(r.status, Object.fromEntries(r.headers));
    res.end(buf);
  })
  .listen(port, () => console.log("listening on " + port));
