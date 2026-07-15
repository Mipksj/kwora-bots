const { onDocumentCreated } = require("firebase-functions/v2/firestore");
const { initializeApp } = require("firebase-admin/app");
const { getFirestore, FieldValue } = require("firebase-admin/firestore");

initializeApp();
const db = getFirestore();

function norm(s) {
  return String(s == null ? "" : s).trim().toLowerCase();
}

function pickReply(rules, text) {
  const t = norm(text);
  let fallback = null;
  for (const r of rules) {
    const type = r.type || "equals";
    const m = norm(r.match);
    if (type === "all") {
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
  return fallback;
}

exports.onBotMessage = onDocumentCreated(
  "chats/{chatId}/messages/{msgId}",
  async (event) => {
    const snap = event.data;
    if (!snap) return;
    const msg = snap.data();
    if (!msg || !msg.from) return;
    if (msg.botReply) return;

    const chatId = event.params.chatId;
    const chatRef = db.collection("chats").doc(chatId);
    const chatSnap = await chatRef.get();
    if (!chatSnap.exists) return;
    const chat = chatSnap.data();

    if (chat.type === "group") return;
    const members = chat.members || [];
    if (members.length !== 2) return;

    const botId = members.find((u) => u !== msg.from);
    if (!botId) return;

    const botSnap = await db.collection("users").doc(botId).get();
    if (!botSnap.exists) return;
    const bot = botSnap.data();
    if (!bot.isBot) return;

    if (!msg.text) return;

    const rulesSnap = await db
      .collection("users").doc(botId)
      .collection("rules").orderBy("order", "asc").get();
    const rules = rulesSnap.docs.map((d) => d.data());
    if (!rules.length) return;

    const hit = pickReply(rules, msg.text);
    if (!hit || !hit.reply) return;

    await chatRef.collection("messages").add({
      from: botId,
      text: String(hit.reply).slice(0, 2000),
      at: FieldValue.serverTimestamp(),
      botReply: true,
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
