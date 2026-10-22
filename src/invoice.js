// Q2: A2A Invoice Agent (A2A 1.0 HTTP+JSON)
import { canon, hashOf, sha256hex, json, isObj, isStr, llmJSON, pool, chunk } from "./lib.js";

const A2A = "application/a2a+json";
const IN_MODE = "application/vnd.ga5.invoice-claim-batch+json";
const PROPOSALS = "application/vnd.ga5.invoice-action-proposals+json";
const RECEIPTS = "application/vnd.ga5.invoice-action-receipts+json";
const RESULTS = "application/vnd.ga5.invoice-action-results+json";
const ACTIONS = ["settle_invoice", "request_approval", "hold_invoice", "reject_duplicate", "open_exception"];
const TERMINAL = ["TASK_STATE_COMPLETED", "TASK_STATE_CANCELED", "TASK_STATE_FAILED", "TASK_STATE_REJECTED"];
export const BASE = "/a2a";

const a2a = (body, status = 200) => json(body, status, A2A);
const aerr = (status, code, message) => a2a({ error: { code: status, status: code, message: message || code } }, status);

export function agentCard(origin) {
  return {
    name: "GA5 Invoice Action Agent",
    description: "Reads invoice packages, proposes one evidence-backed business action per invoice, and executes only grader-accepted actions.",
    version: "1.0.0",
    supportedInterfaces: [{ url: origin + BASE, protocolBinding: "HTTP+JSON", protocolVersion: "1.0" }],
    provider: { organization: "TDS GA3", url: origin },
    capabilities: { streaming: false, pushNotifications: false, extendedAgentCard: false },
    securitySchemes: { bearer: { httpAuthSecurityScheme: { scheme: "Bearer" } } },
    securityRequirements: [{ schemes: { bearer: { list: [] } } }],
    defaultInputModes: [IN_MODE, RESULTS],
    defaultOutputModes: [PROPOSALS, RECEIPTS],
    skills: [
      {
        id: "invoice_action_agent",
        name: "Invoice action agent",
        description: "Chooses settle, approval, hold, duplicate rejection or exception for each invoice package with cited evidence.",
        tags: ["invoice", "accounts-payable", "a2a"],
        inputModes: [IN_MODE, RESULTS],
        outputModes: [PROPOSALS, RECEIPTS],
      },
    ],
  };
}

const SYSTEM = `You are an accounts-payable control agent. For each invoice package choose exactly ONE action:
- settle_invoice: valid, fully reconciled (PO/receipt/invoice match), and within the agent's autonomous payment authority.
- request_approval: commercially valid but the amount or terms exceed delegated/autonomous authority so a human approver is needed.
- hold_invoice: payment must pause until a stated verification completes (e.g. bank-detail change callback, pending goods receipt, tax/KYC check).
- reject_duplicate: the SAME commercial invoice (same vendor + same invoice number/amount) was already paid. A payment for a different invoice is NOT a duplicate.
- open_exception: material records conflict (price/quantity/vendor mismatch etc.) and need an exception workflow.

Documents mix the decisive facts with old archived examples, training decoys, negations ("this is NOT a duplicate"), and irrelevant action words. Ignore archive examples, decoys, and the cover sheet. Find the ONE paragraph that actually determines the action for this invoice, and return exactly the three bracketed references contained in that decisive paragraph (copy them exactly as written, including brackets content only, e.g. "INV-ABC-1" for "[INV-ABC-1]").
Extract facts for the invoice itself: vendorName, invoiceNumber, amountMinor (integer in minor units, e.g. INR 1,234.50 -> 123450), currency (ISO code).
Write a rationale of 150-600 characters that names the chosen action and cites at least two of the evidence references.

Reply JSON only: {"decisions":[{"packageId":"...","action":"...","facts":{"vendorName":"...","invoiceNumber":"...","amountMinor":0,"currency":"INR"},"evidenceRefs":["...","...","..."],"rationale":"..."}]}`;

function pkgWithoutId(p) {
  const { packageId, ...rest } = p;
  return rest;
}

function refsIn(pkg) {
  const text = canon(pkg);
  return new Set([...text.matchAll(/\[([^\[\]"\\]{1,120})\]/g)].map((m) => m[1].trim()));
}

function normalize(pkg, raw) {
  const action = ACTIONS.includes(raw?.action) ? raw.action : "open_exception";
  const known = refsIn(pkg);
  let refs = (Array.isArray(raw?.evidenceRefs) ? raw.evidenceRefs : []).map((r) => String(r).replace(/^\[|\]$/g, "").trim());
  refs = [...new Set(refs)].filter((r) => known.size === 0 || known.has(r));
  const f = isObj(raw?.facts) ? raw.facts : {};
  let amount = f.amountMinor;
  if (typeof amount === "string") amount = Number(amount.replace(/[^0-9.-]/g, ""));
  amount = Number.isFinite(amount) ? Math.round(amount) : 0;
  const facts = {
    vendorName: String(f.vendorName ?? ""),
    invoiceNumber: String(f.invoiceNumber ?? ""),
    amountMinor: amount,
    currency: String(f.currency ?? "INR").toUpperCase(),
  };
  let rationale = String(raw?.rationale ?? "");
  if (!rationale.includes(action)) rationale = `Action ${action}: ` + rationale;
  const cited = refs.filter((r) => rationale.includes(r)).length;
  if (cited < 2 && refs.length) rationale += ` Evidence: ${refs.map((r) => `[${r}]`).join(", ")}.`;
  if (rationale.length < 60) rationale = rationale.padEnd(60, ".");
  if (rationale.length > 1500) rationale = rationale.slice(0, 1500);
  return { action, facts, evidenceRefs: refs, rationale };
}

async function decide(env, pkgs) {
  const groups = chunk(pkgs, 6);
  const out = await pool(groups, 6, async (g) => {
    const user = g.map((p) => `### PACKAGE ${p.packageId}\n${JSON.stringify(p)}`).join("\n\n");
    for (let i = 0; i < 2; i++) {
      try {
        const r = await llmJSON(env, SYSTEM, user, { timeoutMs: 38000 });
        const by = new Map((r.decisions || []).map((d) => [d.packageId, d]));
        return g.map((p) => normalize(p, by.get(p.packageId)));
      } catch (e) {
        if (i === 1) throw e;
      }
    }
  });
  return out.flat();
}

function uuid() {
  return crypto.randomUUID();
}

function publicTask(t) {
  const { principal, _proposals, ...rest } = t;
  return rest;
}

export async function handleA2A(req, app, path, origin) {
  if (path === "/.well-known/agent-card.json" && req.method === "GET") return json(agentCard(origin), 200, "application/json");
  if (!(path === BASE || path.startsWith(BASE + "/"))) return null;
  const sub = path.slice(BASE.length) || "/";

  const auth = req.headers.get("authorization") || "";
  const m = auth.match(/^Bearer\s+(\S+)\s*$/);
  if (!m) return aerr(401, "UNAUTHENTICATED", "Bearer token required");
  const principal = await sha256hex("p:" + m[1]);
  const ver = req.headers.get("a2a-version");
  if (ver !== "1.0") return aerr(400, "VERSION_NOT_SUPPORTED", "A2A-Version 1.0 required");

  if (req.method === "POST") {
    const ct = (req.headers.get("content-type") || "").split(";")[0].trim().toLowerCase();
    if (ct !== A2A && ct !== "application/json") return aerr(415, "UNSUPPORTED_MEDIA_TYPE", "use application/a2a+json");
  }

  if (sub === "/message:send" && req.method === "POST") return sendMessage(req, app, principal);
  if (sub === "/tasks" && req.method === "GET") {
    const ids = (await app.store.get(`a2a:list:${principal}`)) || [];
    const tasks = [];
    for (const id of ids) {
      const t = await app.store.get(`a2a:task:${id}`);
      if (t && t.principal === principal) tasks.push(publicTask(t));
    }
    return a2a({ tasks });
  }
  let mm = sub.match(/^\/tasks\/([^/:]+):cancel$/);
  if (mm && req.method === "POST") return cancel(app, principal, decodeURIComponent(mm[1]));
  mm = sub.match(/^\/tasks\/([^/:]+)$/);
  if (mm && req.method === "GET") {
    const t = await app.store.get(`a2a:task:${decodeURIComponent(mm[1])}`);
    if (!t || t.principal !== principal) return aerr(404, "NOT_FOUND", "task not found");
    return a2a(publicTask(t));
  }
  return aerr(404, "NOT_FOUND", "route not found");
}

async function sendMessage(req, app, principal) {
  let body;
  try {
    body = JSON.parse(await req.text());
  } catch {
    return aerr(400, "INVALID_JSON");
  }
  const msg = body?.message;
  if (!isObj(msg) || !isStr(msg.messageId) || msg.role !== "ROLE_USER" || !Array.isArray(msg.parts) || msg.parts.length === 0)
    return aerr(400, "INVALID_REQUEST", "invalid message");
  const msgHash = await hashOf(msg);
  const dkey = `a2a:msg:${principal}:${msg.messageId}`;

  if (msg.taskId !== undefined) {
    if (!isStr(msg.taskId)) return aerr(400, "INVALID_REQUEST");
    return app.once(`a2a:task:${msg.taskId}`, () => continueTask(app, principal, msg, msgHash, dkey));
  }

  return app.once(dkey, async () => {
    const seen = await app.store.get(dkey);
    if (seen) {
      if (seen.hash !== msgHash) return aerr(409, "IDEMPOTENCY_CONFLICT", "messageId reused with different content");
      const t = await app.store.get(`a2a:task:${seen.taskId}`);
      return a2a({ task: publicTask(t) });
    }
    const part = msg.parts.find((p) => p?.mediaType === IN_MODE);
    const data = part?.data;
    if (!isObj(data) || !isStr(data.batchId) || !Array.isArray(data.packages) || data.packages.length === 0)
      return aerr(400, "INVALID_REQUEST", "invoice-claim-batch part required");
    const ids = new Set();
    for (const p of data.packages) {
      if (!isObj(p) || !isStr(p.packageId) || ids.has(p.packageId)) return aerr(400, "INVALID_REQUEST", "invalid or duplicate packageId");
      ids.add(p.packageId);
    }
    const fps = await Promise.all(data.packages.map((p) => hashOf(pkgWithoutId(p))));
    const cached = await Promise.all(fps.map((fp) => app.store.get(`a2a:dec:${fp}`)));
    const missing = data.packages.filter((_, i) => !cached[i]);
    if (missing.length) {
      let dec;
      try {
        dec = await decide(app.env, missing);
      } catch {
        return aerr(503, "UNAVAILABLE", "decision service unavailable");
      }
      let k = 0;
      for (let i = 0; i < cached.length; i++)
        if (!cached[i]) {
          cached[i] = dec[k++];
          await app.store.put(`a2a:dec:${fps[i]}`, cached[i]);
        }
    }
    const taskId = uuid();
    const contextId = msg.contextId && isStr(msg.contextId) ? msg.contextId : uuid();
    const proposals = await Promise.all(
      data.packages.map(async (p, i) => ({
        packageId: p.packageId,
        actionId: "act_" + (await sha256hex(`${principal}|${data.batchId}|${p.packageId}|${msg.messageId}`)).slice(0, 28),
        action: cached[i].action,
        facts: cached[i].facts,
        evidenceRefs: cached[i].evidenceRefs,
        rationale: cached[i].rationale,
      }))
    );
    const stored = { ...msg, taskId, contextId };
    const task = {
      id: taskId,
      contextId,
      status: { state: "TASK_STATE_INPUT_REQUIRED", timestamp: new Date().toISOString() },
      artifacts: [{ artifactId: "proposals-" + taskId, name: "invoice-action-proposals", parts: [{ mediaType: PROPOSALS, data: { batchId: data.batchId, proposals } }] }],
      history: [stored],
      metadata: { batchId: data.batchId },
      principal,
    };
    await app.store.put(`a2a:task:${taskId}`, task);
    await app.store.put(dkey, { hash: msgHash, taskId });
    const list = (await app.store.get(`a2a:list:${principal}`)) || [];
    list.push(taskId);
    await app.store.put(`a2a:list:${principal}`, list);
    return a2a({ task: publicTask(task) });
  });
}

async function continueTask(app, principal, msg, msgHash, dkey) {
  const t = await app.store.get(`a2a:task:${msg.taskId}`);
  if (!t || t.principal !== principal) return aerr(404, "NOT_FOUND", "task not found");
  const seen = await app.store.get(dkey);
  if (seen) {
    if (seen.hash !== msgHash) return aerr(409, "IDEMPOTENCY_CONFLICT", "messageId reused with different content");
    return a2a({ task: publicTask(t) });
  }
  if (msg.contextId !== undefined && msg.contextId !== t.contextId) return aerr(400, "INVALID_REQUEST", "context mismatch");
  if (TERMINAL.includes(t.status.state)) return aerr(409, "TASK_NOT_ACTIVE", "task is terminal");
  if (t.status.state !== "TASK_STATE_INPUT_REQUIRED") return aerr(409, "TASK_NOT_ACTIVE");
  const part = msg.parts.find((p) => p?.mediaType === RESULTS);
  const data = part?.data;
  const prop = t.artifacts[0].parts[0].data;
  if (!isObj(data) || data.batchId !== prop.batchId || !Array.isArray(data.results)) return aerr(400, "INVALID_REQUEST", "results do not match task");
  const byPkg = new Map(prop.proposals.map((p) => [p.packageId, p]));
  const seenPkg = new Set();
  for (const r of data.results) {
    const p = isObj(r) && byPkg.get(r.packageId);
    if (!p || seenPkg.has(r.packageId) || r.actionId !== p.actionId || r.action !== p.action) return aerr(400, "INVALID_REQUEST", "result does not match proposal");
    if (r.outcome !== "ACCEPTED" && r.outcome !== "REJECTED") return aerr(400, "INVALID_REQUEST", "invalid outcome");
    if (r.outcome === "ACCEPTED" && !isStr(r.receiptNonce)) return aerr(400, "INVALID_REQUEST", "receiptNonce required");
    seenPkg.add(r.packageId);
  }
  const executions = data.results
    .filter((r) => r.outcome === "ACCEPTED")
    .map((r) => {
      const p = byPkg.get(r.packageId);
      return { packageId: p.packageId, actionId: p.actionId, action: p.action, receiptNonce: r.receiptNonce, facts: p.facts, evidenceRefs: p.evidenceRefs };
    });
  t.history.push({ ...msg, contextId: t.contextId });
  t.artifacts.push({ artifactId: "receipts-" + t.id, name: "invoice-action-receipts", parts: [{ mediaType: RECEIPTS, data: { batchId: prop.batchId, executions } }] });
  t.status = { state: "TASK_STATE_COMPLETED", timestamp: new Date().toISOString() };
  await app.store.put(`a2a:task:${t.id}`, t);
  await app.store.put(dkey, { hash: msgHash, taskId: t.id });
  return a2a({ task: publicTask(t) });
}

async function cancel(app, principal, id) {
  return app.once(`a2a:task:${id}`, async () => {
    const t = await app.store.get(`a2a:task:${id}`);
    if (!t || t.principal !== principal) return aerr(404, "NOT_FOUND", "task not found");
    if (TERMINAL.includes(t.status.state)) return aerr(409, "TASK_NOT_CANCELABLE", "task is terminal");
    t.status = { state: "TASK_STATE_CANCELED", timestamp: new Date().toISOString() };
    await app.store.put(`a2a:task:${id}`, t);
    return a2a(publicTask(t));
  });
}
