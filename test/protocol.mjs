// Protocol smoke tests against a running server: node test/protocol.mjs http://localhost:8787
import { canon, sha256hex } from "../src/lib.js";

const BASE = process.argv[2] || "http://localhost:8787";
let fails = 0;
const ok = (c, m) => {
  console.log((c ? "PASS " : "FAIL ") + m);
  if (!c) fails++;
};
const post = (p, b, h = {}) => fetch(BASE + p, { method: "POST", headers: { "content-type": "application/json", ...h }, body: typeof b === "string" ? b : JSON.stringify(b) });

// ---------- mailroom ----------
{
  const kp = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const jwk = await crypto.subtle.exportKey("jwk", kp.publicKey);
  const dossiers = [1, 2].map((i) => ({
    dossierId: "d" + i, partition: "stable_core", receivedAt: "2026-10-01T00:00:00Z", mailbox: "support", objective: "x",
    sources: [{ sourceId: "s" + i, kind: "email", provenance: "external", title: "t", lines: [{ lineId: `d${i}.l1`, text: "Where is order ORD-" + i }] }],
  }));
  const req = { profile: "ga5-mailroom-action-gate/v2", operation: "propose", evaluationId: "ev1", receiptVerifier: { algorithm: "Ed25519", publicKeyJwk: { kty: "OKP", crv: "Ed25519", x: jwk.x } }, corpus: {}, allowedActions: [], dossiers };
  const [r1, r1b] = await Promise.all([post("/mailroom", req), post("/mailroom", req)]);
  const j1 = await r1.json();
  ok(r1.status === 200 && j1.proposals.length === 2, "mailroom propose");
  ok(JSON.stringify(j1) === JSON.stringify(await r1b.json()), "mailroom concurrent replay identical");
  ok(j1.inputDigest === (await sha256hex(canon(dossiers))), "inputDigest");
  ok((await post("/mailroom", { ...req, dossiers: [dossiers[0]] })).status === 409, "mailroom changed content 409");
  ok((await post("/mailroom", { ...req, evaluationId: "ev2", dossiers: [dossiers[0], dossiers[0]] })).status >= 400, "duplicate dossier rejected");
  ok((await post("/mailroom", "{bad")).status === 400, "malformed json 400");
  const receipts = [];
  for (const [i, p] of j1.proposals.entries()) {
    const pd = await sha256hex(canon({ dossierId: p.dossierId, callId: p.callId, action: p.action, target: p.target ?? null, payload: p.payload, evidence: [...p.evidence].sort() }));
    const inner = { dossierId: p.dossierId, callId: p.callId, action: p.action, accepted: i === 0, proposalDigest: pd, receiptId: "rc" + i };
    const msg = canon({ profile: req.profile, evaluationId: "ev1", inputDigest: j1.inputDigest, receipt: inner });
    const sig = Buffer.from(await crypto.subtle.sign({ name: "Ed25519" }, kp.privateKey, new TextEncoder().encode(msg))).toString("base64");
    receipts.push({ ...inner, receiptSignature: sig });
  }
  const commit = { profile: req.profile, operation: "commit", evaluationId: "ev1", inputDigest: j1.inputDigest, receipts };
  const bad = structuredClone(commit);
  bad.receipts[0].receiptSignature = receipts[1].receiptSignature;
  ok((await post("/mailroom", bad)).status >= 400, "bad signature rejected");
  const c1 = await post("/mailroom", commit);
  const cj = await c1.json();
  ok(c1.status === 200 && cj.outcomes[0].status === "executed" && cj.outcomes[1].status === "rejected", "commit outcomes");
  ok(JSON.stringify(cj) === JSON.stringify(await (await post("/mailroom", commit)).json()), "commit replay");
}

// ---------- incident ----------
{
  const body = {
    profile: "ga5-incident-agent/v2", runId: "run-" + Date.now(), agentName: "incident-response", publicMarker: "pm-1",
    sensitive: { accessToken: "SECRET123", privateNote: "NOTE456" },
    incident: { incidentId: "i1", title: "t", service: "api", severity: "SEV-1", transcript: "[ev_1] cpu high\n[ev_2] deploy 42\n[ev_3] noise", allowedRootCauses: ["bad_deploy", "capacity"] },
    toolCatalog: [{ name: "query_metrics", inputSchema: {} }, { name: "get_deploys", inputSchema: {} }, { name: "rollback_deployment", inputSchema: {} }],
    policy: { maximumDiagnostics: 3, effectTools: ["rollback_deployment"], approvalRequiredFor: ["rollback_deployment", "disable_feature"], doNotExport: [] },
  };
  const tp = "00-" + "a".repeat(32) + "-" + "b".repeat(16) + "-01";
  const r = await post("/v2/incidents", body, { traceparent: tp, tracestate: "k=v" });
  const j = await r.json();
  ok(r.status === 200 && j.status === "waiting" && j.dispatches.length >= 1, "incident create");
  ok(j.dispatches[0].traceparent.startsWith("00-" + "a".repeat(32)), "trace continued");
  ok(JSON.stringify(j) === JSON.stringify(await (await post("/v2/incidents", body, { traceparent: tp })).json()), "incident replay");
  ok((await post("/v2/incidents", { ...body, publicMarker: "x" })).status === 409, "incident conflict");
  const d = j.dispatches[0];
  const rc1 = { receiptId: "r1", outcomes: [{ actionId: d.actionId, callId: d.callId, attempt: 1, status: 503, resultClass: "unavailable", nonce: "n1" }] };
  const j2 = await (await post(`/v2/incidents/${body.runId}/receipts`, rc1)).json();
  ok(j2.dispatches[0]?.attempt === 2 && j2.approvals.length === 0, "503 retry");
  const j3 = await (await post(`/v2/incidents/${body.runId}/receipts`, { receiptId: "r2", outcomes: [{ actionId: d.actionId, callId: d.callId, attempt: 2, status: 200, resultClass: "diagnosis_confirmed", nonce: "n2" }] })).json();
  console.log("  after diag:", j3.status, j3.dispatches?.length, j3.approvals?.length);
  let last = j3;
  if (j3.approvals?.length) {
    last = await (await post(`/v2/incidents/${body.runId}/receipts`, { receiptId: "r3", approvals: [{ approvalId: j3.approvals[0].approvalId, decision: "approved", nonce: "n3" }] })).json();
    ok(last.dispatches[0]?.approvalNonce === "n3", "effect after approval");
  }
  if (last.dispatches?.length) {
    const e = last.dispatches[0];
    last = await (await post(`/v2/incidents/${body.runId}/receipts`, { receiptId: "r4", outcomes: [{ actionId: e.actionId, callId: e.callId, attempt: 1, status: 200, resultClass: "effect_applied", nonce: "n4" }] })).json();
  }
  ok(last.status === "completed" && last.otlp, "incident completed");
  const s = JSON.stringify(last);
  ok(!s.includes("SECRET123") && !s.includes("NOTE456"), "no sensitive leak");
  ok(JSON.stringify(j2) === JSON.stringify(await (await post(`/v2/incidents/${body.runId}/receipts`, rc1)).json()), "receipt replay");
  ok((await post(`/v2/incidents/${body.runId}/receipts`, { ...rc1, outcomes: [] })).status === 409, "receipt conflict");
  const g = await (await fetch(`${BASE}/v2/incidents/${body.runId}`)).json();
  ok(g.status === "completed", "GET state");
  console.log("  spans:", last.otlp.resourceSpans[0].scopeSpans[0].spans.map((x) => x.name).join(" | "));
}

// ---------- A2A ----------
{
  const H = { "content-type": "application/a2a+json", "a2a-version": "1.0", authorization: "Bearer tokA" };
  const card = await (await fetch(BASE + "/.well-known/agent-card.json")).json();
  ok(card.skills[0].id === "invoice_action_agent", "agent card");
  ok((await fetch(BASE + "/a2a/tasks")).status === 401, "no auth 401");
  ok((await fetch(BASE + "/a2a/tasks", { headers: { ...H, "a2a-version": "0.3" } })).status === 400, "bad version 400");
  const msg = { messageId: "m-" + Date.now(), role: "ROLE_USER", parts: [{ mediaType: "application/vnd.ga5.invoice-claim-batch+json", data: { batchId: "b1", policyRevision: "p1", packages: [{ packageId: "pk1", docs: "[R-1] [R-2] [R-3]" }, { packageId: "pk2", docs: "[R-4]" }] } }] };
  const send = (m, cfg = { returnImmediately: false }) => fetch(BASE + "/a2a/message:send", { method: "POST", headers: H, body: JSON.stringify({ message: m, configuration: cfg }) });
  const [a, b] = await Promise.all([send(msg), send(msg, { returnImmediately: true })]);
  const ta = (await a.json()).task;
  const tb = (await b.json()).task;
  ok(ta.status.state === "TASK_STATE_INPUT_REQUIRED" && ta.id === tb.id, "send + concurrent dedupe");
  ok((await send({ ...msg, parts: [{ ...msg.parts[0], data: { ...msg.parts[0].data, batchId: "b2" } }] })).status === 409, "idempotency conflict");
  const other = await fetch(BASE + "/a2a/tasks/" + ta.id, { headers: { ...H, authorization: "Bearer tokB" } });
  ok(other.status === 404, "isolation read");
  ok(JSON.stringify(await (await fetch(BASE + "/a2a/tasks", { headers: { ...H, authorization: "Bearer tokB" } })).json()) === '{"tasks":[]}', "isolation list");
  const props = ta.artifacts[0].parts[0].data.proposals;
  const cont = { messageId: "c-" + Date.now(), taskId: ta.id, contextId: ta.contextId, role: "ROLE_USER", parts: [{ mediaType: "application/vnd.ga5.invoice-action-results+json", data: { batchId: "b1", results: props.map((p, i) => ({ packageId: p.packageId, actionId: p.actionId, action: p.action, outcome: i ? "REJECTED" : "ACCEPTED", receiptNonce: "nonce" + i })) } }] };
  const [x, y] = await Promise.all([send(cont), fetch(BASE + `/a2a/tasks/${ta.id}:cancel`, { method: "POST", headers: H, body: "{}" })]);
  ok([x.status, y.status].sort().join() === "200,409", "receipt/cancel race: " + x.status + "," + y.status);
  const fin = await (await fetch(BASE + "/a2a/tasks/" + ta.id, { headers: H })).json();
  console.log("  final state:", fin.status.state, "artifacts:", fin.artifacts.length);
}

console.log(fails ? `${fails} FAILED` : "ALL PASSED");
