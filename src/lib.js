// Shared helpers: canonical JSON, hashing, responses, LLM calls.

export function canon(v) {
  if (v === null || typeof v !== "object") return JSON.stringify(v);
  if (Array.isArray(v)) return "[" + v.map(canon).join(",") + "]";
  const keys = Object.keys(v).filter((k) => v[k] !== undefined).sort();
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + canon(v[k])).join(",") + "}";
}

export async function sha256hex(str) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(str));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export const hashOf = (v) => sha256hex(canon(v));

export function json(body, status = 200, type = "application/json") {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": type, "cache-control": "no-store" },
  });
}

export function err(status, code, message, type) {
  return json({ error: { code, message: message || code } }, status, type);
}

export async function readJson(req, maxBytes = 4 * 1024 * 1024) {
  const text = await req.text();
  if (text.length > maxBytes) throw new HttpError(413, "BODY_TOO_LARGE");
  try {
    return JSON.parse(text);
  } catch {
    throw new HttpError(400, "INVALID_JSON");
  }
}

export class HttpError extends Error {
  constructor(status, code, message) {
    super(message || code);
    this.status = status;
    this.code = code;
  }
}

export const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
export const isStr = (v) => typeof v === "string" && v.length > 0;

export function randHex(bytes) {
  const a = new Uint8Array(bytes);
  crypto.getRandomValues(a);
  return [...a].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function modelName(env) {
  return env.LLM_API_KEY ? env.LLM_MODEL || "gpt-4.1-mini" : env.WORKERS_AI_MODEL || "@cf/meta/llama-3.3-70b-instruct-fp8-fast";
}

// Calls an OpenAI-compatible endpoint (AI Pipe by default), or Workers AI when no key is set.
// Returns the parsed JSON object the model produced.
export async function llmJSON(env, system, user, { timeoutMs = 40000, maxTokens = 8000 } = {}) {
  const messages = [
    { role: "system", content: system },
    { role: "user", content: user },
  ];
  let text;
  if (env.LLM_MOCK) return {};
  if (env.LLM_API_KEY) {
    const base = (env.LLM_BASE_URL || "https://aipipe.org/openai/v1").replace(/\/$/, "");
    const ctl = new AbortController();
    const t = setTimeout(() => ctl.abort(), timeoutMs);
    try {
      const r = await fetch(base + "/chat/completions", {
        method: "POST",
        signal: ctl.signal,
        headers: { "content-type": "application/json", authorization: "Bearer " + env.LLM_API_KEY },
        body: JSON.stringify({
          model: modelName(env),
          messages,
          temperature: 0,
          max_tokens: maxTokens,
          response_format: { type: "json_object" },
        }),
      });
      if (!r.ok) throw new Error("LLM HTTP " + r.status + " " + (await r.text()).slice(0, 300));
      const j = await r.json();
      text = j.choices?.[0]?.message?.content || "";
    } finally {
      clearTimeout(t);
    }
  } else if (env.AI) {
    const r = await env.AI.run(modelName(env), { messages, max_tokens: maxTokens, temperature: 0 });
    text = typeof r.response === "string" ? r.response : JSON.stringify(r.response);
  } else {
    throw new Error("No LLM configured");
  }
  return parseLooseJson(text);
}

export function parseLooseJson(text) {
  try {
    return JSON.parse(text);
  } catch {}
  const m = text.match(/```(?:json)?\s*([\s\S]*?)```/);
  if (m) {
    try {
      return JSON.parse(m[1]);
    } catch {}
  }
  const s = text.indexOf("{");
  const e = text.lastIndexOf("}");
  if (s >= 0 && e > s) return JSON.parse(text.slice(s, e + 1));
  throw new Error("Model did not return JSON");
}

// Run async fn over items with limited concurrency.
export async function pool(items, limit, fn) {
  const out = new Array(items.length);
  let i = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (i < items.length) {
      const k = i++;
      out[k] = await fn(items[k], k);
    }
  });
  await Promise.all(workers);
  return out;
}

export function chunk(arr, n) {
  const out = [];
  for (let i = 0; i < arr.length; i += n) out.push(arr.slice(i, i + n));
  return out;
}
