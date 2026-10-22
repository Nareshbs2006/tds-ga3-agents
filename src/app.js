// Routes requests to the three agents. `store` is { get(key), put(key, value) }.
import { err, json } from "./lib.js";
import { handleMailroom } from "./mailroom.js";
import { handleIncidents } from "./incident.js";
import { handleA2A } from "./invoice.js";

export function createApp(store, env) {
  const inflight = new Map();
  const app = {
    store,
    env,
    // Serialize work per key so concurrent duplicates share one result.
    once(key, fn) {
      const prev = inflight.get(key) || Promise.resolve();
      const next = prev.catch(() => {}).then(fn);
      const tail = next.then(
        (r) => r,
        () => {}
      );
      inflight.set(key, tail);
      tail.then(() => {
        if (inflight.get(key) === tail) inflight.delete(key);
      });
      // Clone so each waiter gets an unread body.
      return next.then((r) => r.clone());
    },
  };

  return async function fetch(req) {
    const url = new URL(req.url);
    const origin = env.PUBLIC_ORIGIN || url.origin;
    const path = url.pathname;
    try {
      if (path === "/" || path === "/health") return json({ ok: true, service: "tds-ga3-agents" });
      if (path === "/mailroom" || path === "/mailroom/") {
        if (req.method !== "POST") return err(405, "METHOD_NOT_ALLOWED");
        return await handleMailroom(req, app);
      }
      if (path.startsWith("/v2/incidents")) return await handleIncidents(req, app, path);
      const r = await handleA2A(req, app, path, origin);
      if (r) return r;
      return err(404, "NOT_FOUND");
    } catch (e) {
      console.error(e);
      return err(e.status || 500, e.code || "INTERNAL_ERROR");
    }
  };
}
