// ============================================================
//  沐曜 AI 客服系統 — 後端(Vercel 版,單一檔案)
//  路由(都在 /api 底下):
//    GET  /api/health         健康檢查
//    GET  /api/auth-start     開始授權賣場(會轉到蝦皮登入授權頁)
//    GET  /api/auth-callback  授權完成後,蝦皮把 code 導回這裡 → 換 token 存起來
//    POST /api/shopee-push    蝦皮把買家訊息推到這裡
//
//  第一階段(現在):把「真實訊息」接進來、存進資料庫、出現在後台(待客服處理)。
//  先「不」自動回覆(安全),等確認訊息格式正確、送訊息 API 也通,再開自動回。
// ============================================================

import crypto from "node:crypto";

// ---- 環境變數(部署時在 Vercel 設定,不寫死在程式裡)----
const PARTNER_ID = process.env.SHOPEE_PARTNER_ID || "";
const PARTNER_KEY = process.env.SHOPEE_PARTNER_KEY || "";
// 蝦皮「推送」用的驗證金鑰(Set Push 頁 Generate 的那組);沒設就退回用 PARTNER_KEY
const PUSH_KEY = process.env.SHOPEE_PUSH_KEY || process.env.SHOPEE_PARTNER_KEY || "";
const SHOPEE_HOST = process.env.SHOPEE_HOST || "https://partner.shopeemobile.com";
const SB_URL = process.env.SUPABASE_URL || "";
const SB_KEY = process.env.SUPABASE_SERVICE_KEY || "";
const COMPANY_NAME = process.env.COMPANY_NAME || "沐曜實業";

// Vercel:不要自動解析 body,我們要原始內容來驗簽章
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
    // 對蝦皮 push 一律回 200,避免它一直重送
    return text(res, 200, "ok");
  }
}

// ============================================================
//  蝦皮簽章
// ============================================================
function signPublic(path, ts) {
  return crypto.createHmac("sha256", PARTNER_KEY).update(`${PARTNER_ID}${path}${ts}`).digest("hex");
}
function signShop(path, ts, accessToken, shopId) {
  return crypto.createHmac("sha256", PARTNER_KEY)
    .update(`${PARTNER_ID}${path}${ts}${accessToken}${shopId}`).digest("hex");
}

// ============================================================
//  授權:開始 → 轉到蝦皮授權頁
// ============================================================
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

// ============================================================
//  授權:蝦皮導回 → 用 code 換 token → 存進 shops
// ============================================================
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
  if (!data.access_token) {
    return html(res, 500, `換取 token 失敗:${JSON.stringify(data)}`);
  }

  const expireAt = new Date(Date.now() + (data.expire_in || 14400) * 1000).toISOString();
  const company = await sbGetCompanyId();

  // 已存在同一個蝦皮賣場 → 更新;否則新增
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
//  接收蝦皮推送(買家訊息等)
//  v1:驗簽章(記錄結果)→ 存原始內容 → 盡量解析成一則訊息(待客服)→ 回 200
// ============================================================
async function shopeePush(req, res, base) {
  const raw = await readRawBody(req);
  const auth = req.headers["authorization"] || "";
  const callbackUrl = `${base}/api/shopee-push`;
  // 蝦皮推送簽章 = HMAC-SHA256(push_key, callbackUrl + raw_body)
  const expect = crypto.createHmac("sha256", PUSH_KEY).update(`${callbackUrl}${raw}`).digest("hex");
  const sigOk = auth && auth.toLowerCase() === expect.toLowerCase();

  let body = {};
  try { body = JSON.parse(raw || "{}"); } catch {}

  // ===== 偵錯用:把驗簽線索一起存進 push_logs(找到問題後可移除)=====
  const debug = {
    callback_url_used: callbackUrl,
    push_key_len: PUSH_KEY.length,
    push_key_source: process.env.SHOPEE_PUSH_KEY ? "PUSH_KEY" : "fallback_PARTNER_KEY",
    auth_head: auth.slice(0, 16),
    expect_head: expect.slice(0, 16),
  };
  await sb("push_logs", "POST", { sig_ok: !!sigOk, body: { ...body, _debug: debug } }).catch(() => {});
  // ================================================================

  // 盡量解析「聊聊訊息」→ 建一則待處理訊息
  try {
    await tryHandleChat(body);
  } catch (e) { console.error("parse chat error:", e); }

  return text(res, 200, "ok");
}

async function tryHandleChat(body) {
  // 蝦皮 push 格式:{ shop_id, code, data: {...} }
  const shopId = body.shop_id || body.data?.shop_id;
  const d = body.data || {};
  const content = d.content || d.message || {};
  // 各種可能欄位,盡量抓文字
  const messageText =
    content.text || content?.content?.text || d.message_text || d.text || null;
  const buyerId = d.from_id || d.from_user_id || content.from_id || null;
  const buyerName = d.from_user_name || d.from_name || content.from_user_name || null;
  const conversationId = d.conversation_id || content.conversation_id || null;

  if (!shopId || !messageText) return; // 不是聊聊訊息就略過(已記在 push_logs)

  const shops = await sb(`shops?shopee_shop_id=eq.${shopId}&select=id,company_id`);
  if (!shops.length) return; // 找不到對應賣場
  const shop = shops[0];

  await sb("messages", "POST", {
    company_id: shop.company_id,
    shop_id: shop.id,
    conversation_id: conversationId ? String(conversationId) : null,
    buyer_id: buyerId ? String(buyerId) : null,
    buyer_name: buyerName || null,
    customer_message: String(messageText),
    status: "pending",
  });
}

// ============================================================
//  Supabase REST 小工具(用 service key,可寫入)
// ============================================================
async function sb(pathAndQuery, method = "GET", bodyObj) {
  const r = await fetch(`${SB_URL}/rest/v1/${pathAndQuery}`, {
    method,
    headers: {
      apikey: SB_KEY,
      Authorization: `Bearer ${SB_KEY}`,
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

// ============================================================
//  小工具
// ============================================================
async function readRawBody(req) {
  if (typeof req.body === "string") return req.body;
  if (Buffer.isBuffer(req.body)) return req.body.toString("utf8");
  const chunks = [];
  for await (const c of req) chunks.push(c);
  return Buffer.concat(chunks).toString("utf8");
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
