/**
 * Kwora Bots — серверная логика ботов.
 * Слой 1: правила текст->текст (equals) в личных чатах.
 * Деплой: GitHub Actions (см. .github/workflows/deploy.yml).
 */
const { onDocumentCreated } = require("firebase-functions/v2/firestore");
const { initializeApp } = require("firebase-admin/app");
const { getFirestore, FieldValue } = require("firebase-admin/firestore");

initializeApp();
const db = getFirestore();

/* нормализация текста для сравнения: тримминг + нижний регистр */
function norm(s) {
  return String(s == null ? "" : s).trim().toLowerCase();
}

/* подбор ответа по правилам бота */
function pickReply(rules, text) {
  const t = norm(text);
  let fallback = null;

  // правила отсортированы по order; идём по порядку, первое совпадение — победитель
  for (const r of rules) {
    const type = r.type || "equals";
    const m = norm(r.match);

    if (type === "all") {           // ответ на любое сообщение
      if (fallback === null) fallback = r;
      continue;
    }
    if (!m) continue;

    if (type === "equals" && t === m) return r;
    if (type === "contains" && t.includes(m)) return r;
    if (type === "command") {
      const cmd = m.startsWith("/") ? m : "/" + m;
      if (t === cmd || t.startsWith(cmd + " ")) return r;
    }
  }
  return fallback; // либо правило "на всё", либо null
}

exports.onBotMessage = onDocumentCreated(
  "chats/{chatId}/messages/{msgId}",
  async (event) => {
    const snap = event.data;
    if (!snap) return;
    const msg = snap.data();
    if (!msg || !msg.from) return;

    // защита от эха: если сообщение отправил сам бот — выходим
    if (msg.botReply) return;

    const chatId = event.params.chatId;
    const chatRef = db.collection("chats").doc(chatId);
    const chatSnap = await chatRef.get();
    if (!chatSnap.exists) return;
    const chat = chatSnap.data();

    // слой 1 — только личные чаты (2 участника)
    if (chat.type === "group") return;
    const members = chat.members || [];
    if (members.length !== 2) return;

    // получатель = второй участник
    const botId = members.find((u) => u !== msg.from);
    if (!botId) return;

    // это бот?
    const botSnap = await db.collection("users").doc(botId).get();
    if (!botSnap.exists) return;
    const bot = botSnap.data();
    if (!bot.isBot) return;

    // текстовые сообщения (фото пока пропускаем на слое 1)
    if (!msg.text) return;

    // читаем правила бота
    const rulesSnap = await db
      .collection("users").doc(botId)
      .collection("rules").orderBy("order", "asc").get();
    const rules = rulesSnap.docs.map((d) => d.data());
    if (!rules.length) return;

    const hit = pickReply(rules, msg.text);
    if (!hit || !hit.reply) return;

    // пишем ответ от имени бота
    await chatRef.collection("messages").add({
      from: botId,
      text: String(hit.reply).slice(0, 2000),
      at: FieldValue.serverTimestamp(),
      botReply: true, // помечаем, чтобы не зациклиться
    });

    await chatRef.set(
      {
        lastText: String(hit.reply).slice(0, 80),
        lastFrom: botId,
        lastAt: FieldValue.serverTimestamp(),
      },
      { merge: true }
    );
  }
);
