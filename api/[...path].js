// ============================================================
//  沐曜 AI 客服系統 — 後端(Vercel 版,單一檔案)
//  ★ 這一版是「自動試簽」偵錯版:一次用多種組法算簽章,
//    找出哪一種等於蝦皮送來的 auth,把答案記進 push_logs。
//    找到正確組法後,再換回乾淨版。
// ============================================================

import crypto from "node:crypto";

const PARTNER_ID = process.env.SHOPEE_PARTNER_ID || "";
const PARTNER_KEY = process.env.SHOPEE_PARTNER_KEY || "";
const PUSH_KEY = process.env.SHOPEE_PUSH_KEY || process.env.SHOPEE_PARTNER_KEY || "";
const SHOPEE_HOST = process.env.SHOPEE_HOST || "https://partner.shopeemobile.com";
const SB_URL = process.env.SUPABASE_URL || "";
const SB_KEY = process.env.SUPABASE_SERVICE_KEY || "";
const COMPANY_NAME = process.env.COMPANY_NAME || "沐曜實業";

export const config = { api: { bodyParser: false } };

export default async function handler(req, res) {
  try {
    const host = req.headers["x-forwarded-host"] || req.headers.host;
    const proto = req.headers["x-forwarded-proto"] || "https";
    const base = `${proto}://${host}`;
    const url = new URL(req.url, base);
    const path = url.pathname.replace(/^\/api/, "");

    if (path === "/health" || path === "" || path === "/") {
      return text(res, 200, "沐曜客服系統 後端運作中 ✅");
    }
    if (path === "/auth-start") return authStart(req, res, base);
    if (path === "/auth-callback") return authCallback(req, res, url);
    if (path === "/shopee-push") return shopeePush(req, res, base);

    return text(res, 404, "Not found");
  } catch (e) {
    console.error("handler error:", e);
    return text(res, 200, "ok");
  }
}

function signPublic(path, ts) {
  return crypto.createHmac("sha256", PARTNER_KEY).update(`${PARTNER_ID}${path}${ts}`).digest("hex");
}

function authStart(req, res, base) {
  const path = "/api/v2/shop/auth_partner";
  const ts = Math.floor(Date.now() / 1000);
  const sign = signPublic(path, ts);
  const redirect = `${base}/api/auth-callback`;
  const authUrl = `${SHOPEE_HOST}${path}?partner_id=${PARTNER_ID}&timestamp=${ts}&sign=${sign}&redirect=${encodeURIComponent(redirect)}`;
  res.statusCode = 302;
  res.setHeader("Location", authUrl);
  res.end();
}

async function authCallback(req, res, url) {
  const code = url.searchParams.get("code");
  const shopId = url.searchParams.get("shop_id");
  if (!code || !shopId) return html(res, 400, "缺少 code 或 shop_id,授權失敗。");

  const path = "/api/v2/auth/token/get";
  const ts = Math.floor(Date.now() / 1000);
  const sign = signPublic(path, ts);
  const tokenUrl = `${SHOPEE_HOST}${path}?partner_id=${PARTNER_ID}&timestamp=${ts}&sign=${sign}`;

  const r = await fetch(tokenUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ code, shop_id: Number(shopId), partner_id: Number(PARTNER_ID) }),
  });
  const data = await r.json();
  if (!data.access_token) return html(res, 500, `換取 token 失敗:${JSON.stringify(data)}`);

  const expireAt = new Date(Date.now() + (data.expire_in || 14400) * 1000).toISOString();
  const company = await sbGetCompanyId();
  const existing = await sb(`shops?shopee_shop_id=eq.${shopId}&select=id`);
  if (existing.length) {
    await sb(`shops?id=eq.${existing[0].id}`, "PATCH", {
      access_token: data.access_token, refresh_token: data.refresh_token, token_expire_at: expireAt, active: true,
    });
  } else {
    await sb("shops", "POST", {
      company_id: company, name: `蝦皮賣場 ${shopId}`, shopee_shop_id: Number(shopId),
      access_token: data.access_token, refresh_token: data.refresh_token, token_expire_at: expireAt, active: true,
    });
  }
  return html(res, 200, `✅ 賣場授權成功!(shop_id: ${shopId})<br>可以關掉這個視窗了。`);
}

// ============================================================
//  ★ 自動試簽:一次算多種組法,找出哪一種 = 蝦皮的 auth
// ============================================================
async function shopeePush(req, res, base) {
  const raw = await readRawBody(req);
  const auth = (req.headers["authorization"] || "").toLowerCase();
  const url1 = `${base}/api/shopee-push`;      // 程式現用
  const url2 = `${url1}/`;                       // 尾巴多斜線
  const push = PUSH_KEY;
  const partner = PARTNER_KEY;

  const H = (key, msg) => crypto.createHmac("sha256", key).update(msg).digest("hex").toLowerCase();

  // 各種候選組法(key × base string)
  const candidates = {
    "push_urlbody":        H(push, `${url1}${raw}`),          // push_key, url+body   ← 現用
    "push_urlbody_slash":  H(push, `${url2}${raw}`),          // push_key, url(/)+body
    "push_bodyonly":       H(push, `${raw}`),                 // push_key, 只有 body
    "partner_urlbody":     H(partner, `${url1}${raw}`),       // partner_key, url+body
    "push_url_pipe_body":  H(push, `${url1}|${raw}`),         // push_key, url|body
    "push_partnerid_url_body": H(push, `${PARTNER_ID}${url1}${raw}`), // push_key, partnerid+url+body
  };

  // 找出哪一個對上蝦皮
  let matched = "NONE";
  for (const [name, val] of Object.entries(candidates)) {
    if (auth && val === auth) { matched = name; break; }
  }
  const sigOk = matched !== "NONE";

  let body = {};
  try { body = JSON.parse(raw || "{}"); } catch {}

  const debug = {
    matched_variant: matched,        // ★ 哪一種組法對上了
    auth_shopee: auth.slice(0, 20),
    raw_source: req._rawSource || "unknown",
    raw_len: raw ? raw.length : 0,
    tried: Object.fromEntries(Object.entries(candidates).map(([k, v]) => [k, v.slice(0, 12)])),
  };
  await sb("push_logs", "POST", { sig_ok: !!sigOk, body: { ...body, _debug: debug } }).catch(() => {});

  try { await tryHandleChat(body); } catch (e) { console.error("parse chat error:", e); }
  return text(res, 200, "ok");
}

async function tryHandleChat(body) {
  const shopId = body.shop_id || body.data?.shop_id;
  const d = body.data || {};
  const content = d.content || d.message || {};
  const messageText = content.text || content?.content?.text || d.message_text || d.text || null;
  const buyerId = d.from_id || d.from_user_id || content.from_id || null;
  const buyerName = d.from_user_name || d.from_name || content.from_user_name || null;
  const conversationId = d.conversation_id || content.conversation_id || null;
  if (!shopId || !messageText) return;
  const shops = await sb(`shops?shopee_shop_id=eq.${shopId}&select=id,company_id`);
  if (!shops.length) return;
  const shop = shops[0];
  await sb("messages", "POST", {
    company_id: shop.company_id, shop_id: shop.id,
    conversation_id: conversationId ? String(conversationId) : null,
    buyer_id: buyerId ? String(buyerId) : null,
    buyer_name: buyerName || null,
    customer_message: String(messageText), status: "pending",
  });
}

async function sb(pathAndQuery, method = "GET", bodyObj) {
  const r = await fetch(`${SB_URL}/rest/v1/${pathAndQuery}`, {
    method,
    headers: {
      apikey: SB_KEY, Authorization: `Bearer ${SB_KEY}`,
      "Content-Type": "application/json",
      Prefer: method === "POST" ? "return=representation" : "return=minimal",
    },
    body: bodyObj ? JSON.stringify(bodyObj) : undefined,
  });
  if (method === "GET") return r.json();
  try { return await r.json(); } catch { return null; }
}
async function sbGetCompanyId() {
  const rows = await sb(`companies?name=eq.${encodeURIComponent(COMPANY_NAME)}&select=id`);
  return rows[0]?.id;
}

async function readRawBody(req) {
  try {
    if (typeof req.arrayBuffer === "function") {
      const buf = Buffer.from(await req.arrayBuffer());
      if (buf && buf.length) { req._rawSource = "arrayBuffer"; return buf.toString("utf8"); }
    }
  } catch {}
  try {
    if (typeof req[Symbol.asyncIterator] === "function") {
      const chunks = [];
      for await (const c of req) chunks.push(typeof c === "string" ? Buffer.from(c) : c);
      if (chunks.length) { req._rawSource = "stream"; return Buffer.concat(chunks).toString("utf8"); }
    }
  } catch {}
  if (typeof req.body === "string") { req._rawSource = "body_string"; return req.body; }
  if (Buffer.isBuffer(req.body)) { req._rawSource = "body_buffer"; return req.body.toString("utf8"); }
  if (req.body && typeof req.body === "object") { req._rawSource = "body_object_restringify"; return JSON.stringify(req.body); }
  req._rawSource = "empty";
  return "";
}
function text(res, code, s) {
  res.statusCode = code;
  res.setHeader("Content-Type", "text/plain; charset=utf-8");
  res.end(s);
}
function html(res, code, s) {
  res.statusCode = code;
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.end(`<!doctype html><meta charset="utf-8"><body style="font-family:sans-serif;padding:40px;text-align:center;font-size:18px">${s}</body>`);
}
