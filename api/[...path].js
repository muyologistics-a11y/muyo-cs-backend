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
// 預設 AI 設定(當客戶自己沒有在後台填 AI 供應商/金鑰時,退回用這組;
// 目前主要給我們自己的測試帳號用)。沒設金鑰就跳過生成,不擋收訊流程。
const DEFAULT_AI_PROVIDER = process.env.OPENAI_API_KEY ? "openai" : "gemini";
const DEFAULT_OPENAI_API_KEY = process.env.OPENAI_API_KEY || "";
const DEFAULT_OPENAI_MODEL = process.env.OPENAI_MODEL || "gpt-4o-mini";
const DEFAULT_GEMINI_API_KEY = process.env.GEMINI_API_KEY || "";
const DEFAULT_GEMINI_MODEL = process.env.GEMINI_MODEL || "gemini-2.0-flash";
// FAQ之外/AI判斷自己答不出來/API呼叫技術性失敗時,一律用這段公版頂著,而不是留空白。
// 想改措辭直接在 Vercel 改這個環境變數就好,不用動程式碼、不用重新部署等太久。
const FALLBACK_REPLY_TEMPLATE = process.env.FALLBACK_REPLY_TEMPLATE ||
  "目前為客服休息時間，請耐心等候。\n待客服小編上班時段會盡快協助您處理 🙏";

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

  // 生成 AI 草稿(參考同一段對話的歷史訊息 + 店家 FAQ 當上下文);失敗也不擋訊息存檔,草稿留空即可
  let aiDraft = "";
  try {
    aiDraft = await generateAiDraft({
      companyId: shop.company_id, shopId: shop.id, conversationId, buyerId, buyerName, messageText,
    });
  } catch (e) {
    console.error("generateAiDraft error:", e);
  }

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
    ai_draft: aiDraft || null,
  }).catch(() => {});
}

// ============================================================
//  AI 草稿生成(OpenAI)
//  ★ 只生成「草稿」,不會自動送出 — 仍由客服在後台審核/編輯後才核准送出。
//  ★ 會參考 faqs 表裡符合的常見問題當作回答依據;沒接的是商品/庫存/訂單
//    資料,所以提示詞會請 AI 避免亂編現貨、價格等 FAQ 裡也沒有的具體承諾。
// ============================================================
async function fetchConversationHistory({ shopId, conversationId, buyerId }) {
  if (!conversationId && !buyerId) return [];
  const filter = conversationId
    ? `conversation_id=eq.${encodeURIComponent(String(conversationId))}`
    : `buyer_id=eq.${encodeURIComponent(String(buyerId))}`;
  const rows = await sb(
    `messages?shop_id=eq.${shopId}&${filter}&select=customer_message,reply_text,received_at&order=received_at.desc&limit=10`
  ).catch(() => []);
  return Array.isArray(rows) ? rows.reverse() : []; // 轉回「舊到新」方便組提示詞
}

// 從店家的 faqs 表裡,找出跟這句買家訊息「關鍵字對得上」的常見問題。
// faqs.questions 是每個項目自己列的一堆類似問法(例如「運費多少」「免運門檻」…),
// 用簡單的字串包含比對就好,不需要語意搜尋 —— FAQ 內容本來就是店家自己整理的
// 關鍵字,對得上代表買家在問同一件事。
async function fetchRelevantFaqs({ companyId, messageText }) {
  if (!companyId || !messageText) return [];
  const rows = await sb(`faqs?company_id=eq.${companyId}&select=category,questions,answer`).catch(() => []);
  if (!Array.isArray(rows)) return [];
  const text = String(messageText);
  return rows.filter((r) => Array.isArray(r.questions) && r.questions.some((q) => q && text.includes(q)));
}

// 草稿裡絕對不能出現的字(不管什麼情境都不行,例如「取消」— 不分訂單取消、活動取消或其他用法)。
// 之後如果還有其他禁用詞,加進這個陣列就好。
const FORBIDDEN_WORDS = ["取消"];
function containsForbiddenWord(text) {
  return FORBIDDEN_WORDS.some((w) => text.includes(w));
}

// 每個客戶(company)可以在後台自己選 AI 供應商、填自己的金鑰,存在
// autosend_settings 那一列。沒填的話用我們自己的預設值(給自家測試帳號用)。
async function fetchAiSettings({ companyId }) {
  if (!companyId) return null;
  const rows = await sb(`autosend_settings?company_id=eq.${companyId}&select=ai_provider,ai_api_key,ai_model`).catch(() => []);
  return Array.isArray(rows) && rows[0] ? rows[0] : null;
}

function resolveAiConfig(companySettings) {
  const provider = companySettings?.ai_provider || DEFAULT_AI_PROVIDER;
  const isGemini = provider === "gemini";
  const apiKey = companySettings?.ai_api_key || (isGemini ? DEFAULT_GEMINI_API_KEY : DEFAULT_OPENAI_API_KEY);
  const model = companySettings?.ai_model || (isGemini ? DEFAULT_GEMINI_MODEL : DEFAULT_OPENAI_MODEL);
  return { provider, apiKey, model };
}

// 以下 callOpenAI / callGemini 都回傳 null 代表「技術性失敗」(API出錯、
// 額度用完、網路問題等),用來跟「模型就是回了空字串」這種正常情況區分開來,
// 呼叫端才知道要不要頂公版。
async function callOpenAI(prompt, { apiKey, model }) {
  try {
    const url = "https://api.openai.com/v1/chat/completions";
    const r = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${apiKey}`,
      },
      body: JSON.stringify({
        model,
        messages: [{ role: "user", content: prompt }],
      }),
    });
    const data = await r.json();
    if (!r.ok || data.error) {
      console.error("OpenAI API 呼叫失敗:", r.status, JSON.stringify(data.error || data));
      return null;
    }
    const draft = data?.choices?.[0]?.message?.content || "";
    return draft.trim();
  } catch (e) {
    console.error("OpenAI API 呼叫發生例外:", e);
    return null;
  }
}

async function callGemini(prompt, { apiKey, model }) {
  try {
    const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`;
    const r = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ contents: [{ role: "user", parts: [{ text: prompt }] }] }),
    });
    const data = await r.json();
    if (!r.ok || data.error) {
      console.error("Gemini API 呼叫失敗:", r.status, JSON.stringify(data.error || data));
      return null;
    }
    const draft = data?.candidates?.[0]?.content?.parts?.[0]?.text || "";
    return draft.trim();
  } catch (e) {
    console.error("Gemini API 呼叫發生例外:", e);
    return null;
  }
}

async function callAi(prompt, aiConfig) {
  return aiConfig.provider === "gemini" ? callGemini(prompt, aiConfig) : callOpenAI(prompt, aiConfig);
}

// 客訴類關鍵字:一律直接用公版頂著、不讓 AI 自己判斷要不要接手 ——
// 這種情況一定要真人客服處理,不能讓 AI 自己安撫幾句就算了。
const ESCALATE_KEYWORDS = ["客訴", "投訴", "申訴", "賠償", "求償", "提告", "消保", "消基會", "檢舉", "客服經理"];
function needsHumanEscalation(text) {
  return ESCALATE_KEYWORDS.some((w) => text.includes(w));
}

async function generateAiDraft({ companyId, shopId, conversationId, buyerId, buyerName, messageText }) {
  const companySettings = await fetchAiSettings({ companyId });
  const aiConfig = resolveAiConfig(companySettings);
  if (!aiConfig.apiKey) return ""; // 這個客戶沒填金鑰、也沒有預設可退回,先不生成
  if (needsHumanEscalation(messageText)) return FALLBACK_REPLY_TEMPLATE; // 客訴類,不經過AI判斷,直接交給真人

  const history = await fetchConversationHistory({ shopId, conversationId, buyerId });
  const historyLines = history.flatMap((m) => {
    const lines = [];
    if (m.customer_message) lines.push(`客人: ${m.customer_message}`);
    if (m.reply_text) lines.push(`客服: ${m.reply_text}`);
    return lines;
  });

  const faqs = await fetchRelevantFaqs({ companyId, messageText });
  const faqBlock = faqs.length
    ? faqs.map((f) => `【${f.category}】\n建議回覆:${f.answer}`).join("\n\n")
    : "(沒有找到符合的常見問題,請自行斟酌回答,不確定的地方用提問代替)";

  const basePrompt = [
    `你是「${COMPANY_NAME}」蝦皮賣場的客服人員,請用親切、簡潔、口語化的繁體中文回覆買家,語氣要像真人客服在打字,不要太工整、太像制式範本。`,
    `注意:`,
    `- 可以偶爾自然地加一兩個表情符號(像😊🙏這種常見客服用的),不用每句都加,依內容語氣決定。`,
    `- 可以偶爾出現很輕微、無傷大雅的打字習慣(像少打標點、口語化的贅字),讓語氣更像真人;但「訂單編號、日期、金額、數量」這類具體數字或事實資訊絕對不能打錯或含糊帶過,錯字只能出現在無關緊要的語氣詞上。`,
    `- 如果下面「店家常見問題集」裡有符合買家問題的項目,請優先參考裡面的答案內容回覆,事實/政策細節要跟 FAQ 一致(用字可以自然微調,不用整段照抄);沒有符合的項目才自行斟酌回答。`,
    `- 目前系統還沒有連接商品/庫存/訂單資料,不要編造現貨、價格、出貨日期等具體承諾(除非 FAQ 裡已經寫明);若買家問這些且 FAQ 沒有答案,禮貌詢問更多細節(例如商品連結或名稱)。`,
    `- 這只是「草稿」,會由真人客服審核、視需要修改後才會真正送出,不確定的地方用提問代替武斷回答。`,
    `- 絕對不能出現「取消」這兩個字,不管什麼情境都不行。如果是講「訂單取消」的情況,一律改講「訂單不成立」;其他情境(活動、優惠等)改用「撤回」「暫停」等其他說法,依情境調整。`,
    `- 如果買家的問題完全超出你能處理的範圍 —— 不是「可以用禮貌提問釐清」的一般問題,而是真的需要真人客服才能處理(例如複雜客訴、需要查特定訂單細節、牽涉退換貨判斷、或完全看不懂買家在問什麼) —— 不要亂猜答案,請只回覆這串固定文字、一個字都不要改、不要加任何其他內容:「NEED_HUMAN_FALLBACK」`,
    `- 只要回覆內容本身,不要加任何前綴說明或引號。`,
    ``,
    `店家常見問題集(已篩選出符合這次問題的項目):`,
    faqBlock,
    ``,
    `以下是買家「${buyerName || "買家"}」最近的對話紀錄:`,
    ...historyLines,
    `買家最新訊息: ${messageText}`,
  ].join("\n");

  let draft = await callAi(basePrompt, aiConfig);

  // API 技術性失敗(額度用完、網路問題等):用公版頂著,不要留空白給客服自己想
  if (draft === null) return FALLBACK_REPLY_TEMPLATE;

  // AI 自己判斷答不出來(超出FAQ、需要真人處理):也用公版頂著
  if (draft.includes("NEED_HUMAN_FALLBACK")) return FALLBACK_REPLY_TEMPLATE;

  if (draft && containsForbiddenWord(draft)) {
    // 出現禁用詞,加強提醒重試一次
    const retryPrompt = `${basePrompt}\n\n★ 你上一次的回覆裡出現了禁用詞「取消」,這是絕對不允許的規則,請重新生成一次完整回覆,全文都不能出現「取消」這兩個字。`;
    draft = await callAi(retryPrompt, aiConfig);
    if (draft === null) return FALLBACK_REPLY_TEMPLATE;
    if (draft.includes("NEED_HUMAN_FALLBACK")) return FALLBACK_REPLY_TEMPLATE;
  }

  if (draft && containsForbiddenWord(draft)) {
    // 兩次都沒改過來,用公版頂著,也不要把含禁用詞的內容顯示出來
    console.warn("generateAiDraft: 重試後仍含禁用詞,改用公版回覆");
    return FALLBACK_REPLY_TEMPLATE;
  }

  return draft;
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
//  作法:把該對話(同 conversation_id)還「待處理 / 處理中」的訊息轉成 done,
//        並記註記「已於蝦皮後台回覆」;「已核准待自動送出」的訊息也轉成
//        done,但不覆蓋 reply_text —— 那是核准當下就定案的真正內容,
//        覆蓋掉會導致自動送出腳本(如果剛好在這個空檔讀到)把佔位文字
//        當成真的回覆內容送出去,這是踩過的真實地雷,不能再犯。
//        (共用蝦皮帳號、分不出是誰回的,依佳芬決定:不分人)
//  ★ 包含 approved_to_send 很重要:如果客服已經在我們後台核准、但在
//    自動送出腳本處理之前,又直接在蝦皮後台手動回了,這裡要把那筆
//    排隊中的項目也標記完成,自動送出腳本才不會再送一次重複訊息。
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

  const now = new Date().toISOString();
  const convFilter =
    `messages?shop_id=eq.${shop.id}&conversation_id=eq.${encodeURIComponent(String(conversationId))}`;

  // 還沒核准過的(pending/handling):本來就沒有真正的回覆內容,轉done時補一個說明性文字沒關係
  await sb(`${convFilter}&status=in.(pending,handling)`, "PATCH", {
    status: "done", reply_text: "(已於蝦皮後台回覆)", handled_at: now,
  }).catch(() => {});

  // 已經核准、reply_text 是真正核准內容的(approved_to_send):只改狀態,
  // 不要覆蓋 reply_text,保留核准當下真正的內容當作紀錄。
  await sb(`${convFilter}&status=eq.approved_to_send`, "PATCH", {
    status: "done", handled_at: now,
  }).catch(() => {});
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
