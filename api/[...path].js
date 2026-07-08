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

    // CORS:允許後台網頁(github.io)呼叫;先回應瀏覽器的預檢(OPTIONS)
    setCors(res);
    if (req.method === "OPTIONS") { res.statusCode = 204; res.end(); return; }

    if (path === "/health" || path === "" || path === "/") {
      return text(res, 200, "沐曜客服系統 後端運作中 ✅");
    }
    if (path === "/auth-start") return authStart(req, res, base);
    if (path === "/auth-callback") return authCallback(req, res, url);
    if (path === "/shopee-push") return shopeePush(req, res, base);
    if (path === "/send-reply") return sendReply(req, res);

    return text(res, 404, "Not found");
  } catch (e) {
    console.error("handler error:", e);
    // 對蝦皮 push 一律回 200,避免它一直重送
    return text(res, 200, "ok");
  }
}

// CORS 標頭:允許後台網頁跨網域呼叫送訊 API
function setCors(res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
}

// ============================================================
//  蝦皮簽章(一般 API 用)
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
//  驗簽章 → 存原始內容 → 解析成一則訊息(待客服,防重複)→ 回 200
// ============================================================
async function shopeePush(req, res, base) {
  const raw = await readRawBody(req);
  const auth = (req.headers["authorization"] || "").toLowerCase();
  const callbackUrl = `${base}/api/shopee-push`;
  // ★ 蝦皮推送簽章 = HMAC-SHA256(push_key, callbackUrl + "|" + raw_body),hex
  //    注意中間的「|」直線符號是必要的
  const expect = crypto.createHmac("sha256", PUSH_KEY)
    .update(`${callbackUrl}|${raw}`).digest("hex").toLowerCase();
  const sigOk = !!auth && auth === expect;

  let body = {};
  try { body = JSON.parse(raw || "{}"); } catch {}

  // 記錄推送(保留一份,方便日後查問題)
  await sb("push_logs", "POST", { sig_ok: sigOk, body }).catch(() => {});

  // 簽章沒過 → 不是蝦皮送的(或被竄改),不往下處理
  if (!sigOk) return text(res, 200, "ok");

  // 依 type 分派處理:
  //  - message           : 買家傳來的聊聊訊息 → 建待處理訊息
  //  - notification/mark_as_replied : 賣家(在蝦皮後台)回覆了 → 把該對話轉為已回覆
  try {
    const dtype = body?.data?.type;
    const ctype = body?.data?.content?.type;
    if (dtype === "message") {
      await tryHandleChat(body);
    } else if (dtype === "notification" && ctype === "mark_as_replied") {
      await tryHandleReplied(body);
    }
    // 其他類型的通知目前不處理(已記在 push_logs)
  } catch (e) { console.error("handle push error:", e); }

  return text(res, 200, "ok");
}

// ============================================================
//  解析蝦皮聊聊訊息
//  ★ 實際結構(買家傳給賣場):
//    body.shop_id = 賣場ID(最外層)
//    body.data.type = "message"
//    body.data.content = {
//        to_shop_id(賣場), from_id(買家), from_user_name(買家名),
//        conversation_id, message_id(訊息唯一編號,用來防重複),
//        content: { text: "訊息文字" }   ← 文字在這裡,再深一層
//    }
//  ★ 防重複:同一則訊息蝦皮會推多次,靠 message_id + 資料庫唯一約束擋掉。
// ============================================================
async function tryHandleChat(body) {
  const d = body.data || {};
  if (d.type !== "message") return;          // 只處理聊聊訊息,其他略過
  const c = d.content || {};                 // 訊息主體都在 data.content 底下

  const shopId = c.to_shop_id || body.shop_id || d.shop_id || null;
  const messageText = c.content?.text || c.text || null;
  const buyerId = c.from_id || null;
  const buyerName = c.from_user_name || null;
  const conversationId = c.conversation_id || null;
  const messageId = c.message_id || d.message_id || null;   // 訊息唯一編號

  if (!shopId || !messageText) return;       // 抓不到就略過(已記在 push_logs)

  // 防重複第一關:先查這個 message_id 是否已存在
  if (messageId) {
    const dup = await sb(`messages?shopee_message_id=eq.${encodeURIComponent(String(messageId))}&select=id`);
    if (Array.isArray(dup) && dup.length) return;  // 已經有了 → 跳過,不重複寫
  }

  const shops = await sb(`shops?shopee_shop_id=eq.${shopId}&select=id,company_id`);
  if (!shops.length) return;                 // 找不到對應賣場(可能還沒授權)
  const shop = shops[0];

  // 防重複第二關:寫入時若撞到唯一約束(同一 message_id),Supabase 會回錯,安靜忽略即可
  await sb("messages", "POST", {
    company_id: shop.company_id,
    shop_id: shop.id,
    conversation_id: conversationId ? String(conversationId) : null,
    buyer_id: buyerId ? String(buyerId) : null,
    buyer_name: buyerName || null,
    customer_message: String(messageText),
    shopee_message_id: messageId ? String(messageId) : null,
    status: "pending",
  }).catch(() => {});
}

// ============================================================
//  處理「賣家已回覆」通知(你們在蝦皮後台回覆時,蝦皮會推這個)
//  ★ 實際結構:
//    body.shop_id = 賣場ID
//    body.data.type = "notification"
//    body.data.content = {
//        type: "mark_as_replied",
//        conversation_id: "...",           ← 哪則對話被回了
//        content: { conversation_id: "..." }
//    }
//  作法:把該對話(同 conversation_id)還「待處理 / 處理中」的訊息,
//        全部轉成 done,並記註記「已於蝦皮後台回覆」。
//        (共用蝦皮帳號、分不出是誰回的,依佳芬決定:不分人)
// ============================================================
async function tryHandleReplied(body) {
  const d = body.data || {};
  const c = d.content || {};
  const shopId = body.shop_id || d.shop_id || c.to_shop_id || null;
  const conversationId =
    c.conversation_id || c.content?.conversation_id || d.conversation_id || null;

  if (!shopId || !conversationId) return;   // 資訊不足就略過(已記在 push_logs)

  // 找到對應賣場
  const shops = await sb(`shops?shopee_shop_id=eq.${shopId}&select=id`);
  if (!shops.length) return;
  const shop = shops[0];

  // 把這個對話裡「還沒完成」的訊息(pending / handling)轉成 done。
  // 已經是 done 或 auto_sent 的不動。
  const now = new Date().toISOString();
  await sb(
    `messages?shop_id=eq.${shop.id}` +
    `&conversation_id=eq.${encodeURIComponent(String(conversationId))}` +
    `&status=in.(pending,handling)`,
    "PATCH",
    { status: "done", reply_text: "(已於蝦皮後台回覆)", handled_at: now }
  ).catch(() => {});
}

// ============================================================
//  系統後台「送出給客人」→ 真的送回蝦皮聊聊
//  後台網頁 POST 過來:{ conversation_id, shopee_shop_id, message, to_id }
//  流程:找賣場 → (token 過期先換新) → 呼叫蝦皮送訊 API
// ============================================================
async function sendReply(req, res) {
  const raw = await readRawBody(req);
  let payload = {};
  try { payload = JSON.parse(raw || "{}"); } catch {}
  const { conversation_id, shopee_shop_id, message, to_id, region } = payload;

  if (!shopee_shop_id || !message || (!conversation_id && !to_id)) {
    return json(res, 400, { ok: false, error: "缺少必要參數(shop/message/對象)" });
  }

  // 找賣場 + token
  const shops = await sb(`shops?shopee_shop_id=eq.${shopee_shop_id}&select=id,shopee_shop_id,access_token,refresh_token,token_expire_at`);
  if (!shops.length) return json(res, 404, { ok: false, error: "找不到這個賣場(可能未授權)" });
  let shop = shops[0];

  // token 過期就先換新
  try {
    shop = await ensureFreshToken(shop);
  } catch (e) {
    return json(res, 500, { ok: false, error: "換取新 token 失敗:" + String(e.message || e) });
  }
  if (!shop.access_token) return json(res, 400, { ok: false, error: "這個賣場沒有 access_token,請重新授權" });

  // 呼叫蝦皮送訊 API
  const apiPath = "/api/v2/sellerchat/send_message";
  const ts = Math.floor(Date.now() / 1000);
  const sign = signShop(apiPath, ts, shop.access_token, Number(shop.shopee_shop_id));
  const apiUrl = `${SHOPEE_HOST}${apiPath}?partner_id=${PARTNER_ID}&timestamp=${ts}&sign=${sign}&access_token=${shop.access_token}&shop_id=${shop.shopee_shop_id}`;

  // 送訊主體:蝦皮 sellerchat 用 to_id(買家 id)發送最穩;帶上 region(如 TW),否則會回 not_open_market
  const bodyObj = { message_type: "text", content: { text: String(message) } };
  if (to_id) bodyObj.to_id = Number(to_id);
  else if (conversation_id) bodyObj.conversation_id = String(conversation_id);
  if (region) bodyObj.region = String(region);

  let data = {};
  try {
    const r = await fetch(apiUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(bodyObj),
    });
    data = await r.json();
  } catch (e) {
    return json(res, 502, { ok: false, error: "呼叫蝦皮送訊失敗:" + String(e.message || e) });
  }

  // 蝦皮回應:error 為空字串代表成功
  if (data.error) {
    return json(res, 200, { ok: false, error: data.error, message: data.message || "", shopee: data });
  }
  return json(res, 200, { ok: true, shopee: data });
}

// token 若已過期(或快過期),用 refresh_token 換新的,並存回 shops
async function ensureFreshToken(shop) {
  const now = Date.now();
  const exp = shop.token_expire_at ? new Date(shop.token_expire_at).getTime() : 0;
  // 還有 5 分鐘以上就沿用
  if (exp - now > 5 * 60 * 1000 && shop.access_token) return shop;

  if (!shop.refresh_token) return shop; // 沒 refresh_token 就沒辦法換,交由後續判斷

  const path = "/api/v2/auth/access_token/get";
  const ts = Math.floor(Date.now() / 1000);
  const sign = signPublic(path, ts);
  const url = `${SHOPEE_HOST}${path}?partner_id=${PARTNER_ID}&timestamp=${ts}&sign=${sign}`;
  const r = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      partner_id: Number(PARTNER_ID),
      shop_id: Number(shop.shopee_shop_id),
      refresh_token: shop.refresh_token,
    }),
  });
  const d = await r.json();
  if (!d.access_token) throw new Error(JSON.stringify(d));

  const expireAt = new Date(Date.now() + (d.expire_in || 14400) * 1000).toISOString();
  await sb(`shops?id=eq.${shop.id}`, "PATCH", {
    access_token: d.access_token,
    refresh_token: d.refresh_token || shop.refresh_token,
    token_expire_at: expireAt,
  });
  return { ...shop, access_token: d.access_token, refresh_token: d.refresh_token || shop.refresh_token, token_expire_at: expireAt };
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
// 取得「原始、未被動過的」request body 字串。
// Vercel 有時會先把 body 解析成物件(即使設了 bodyParser:false),
// 那樣算簽章就會失敗。這裡優先用 Web 標準的 arrayBuffer() 直接讀原始位元組,
// 拿不到才依序退回其他方法,確保拿到跟蝦皮簽章時「同一份」原始內容。
async function readRawBody(req) {
  try {
    if (typeof req.arrayBuffer === "function") {
      const buf = Buffer.from(await req.arrayBuffer());
      if (buf && buf.length) return buf.toString("utf8");
    }
  } catch {}
  try {
    if (typeof req[Symbol.asyncIterator] === "function") {
      const chunks = [];
      for await (const c of req) chunks.push(typeof c === "string" ? Buffer.from(c) : c);
      if (chunks.length) return Buffer.concat(chunks).toString("utf8");
    }
  } catch {}
  if (typeof req.body === "string") return req.body;
  if (Buffer.isBuffer(req.body)) return req.body.toString("utf8");
  if (req.body && typeof req.body === "object") return JSON.stringify(req.body);
  return "";
}
function text(res, code, s) {
  res.statusCode = code;
  res.setHeader("Content-Type", "text/plain; charset=utf-8");
  res.end(s);
}
function json(res, code, obj) {
  res.statusCode = code;
  setCors(res);
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.end(JSON.stringify(obj));
}
function html(res, code, s) {
  res.statusCode = code;
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.end(`<!doctype html><meta charset="utf-8"><body style="font-family:sans-serif;padding:40px;text-align:center;font-size:18px">${s}</body>`);
}
