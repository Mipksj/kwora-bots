/**
 * Kwora server: боты + почтовая авторизация (забыл пароль / вход без пароля).
 */
const { onDocumentCreated } = require("firebase-functions/v2/firestore");
const { onCall, HttpsError } = require("firebase-functions/v2/https");
const { initializeApp } = require("firebase-admin/app");
const { getFirestore, FieldValue } = require("firebase-admin/firestore");
const { getAuth } = require("firebase-admin/auth");
const crypto = require("crypto");

initializeApp();
const db = getFirestore();
const adminAuth = getAuth();

/* ---------- EmailJS (отправка кода с сервера) ---------- */
const EJS = {
  service: "service_345gudin",
  template: "template_ny4ohac",
  publicKey: "R4vZz7b0YlLVR7PHe",
  privateKey: "C__BHXLbOfDkJkW3NItyb"
};

const sha = (s) => crypto.createHash("sha256").update(String(s)).digest("hex");
const sixDigits = () => String(Math.floor(100000 + Math.random() * 900000));

async function sendCodeMail(to, code) {
  const res = await fetch("https://api.emailjs.com/api/v1.0/email/send", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      service_id: EJS.service,
      template_id: EJS.template,
      user_id: EJS.publicKey,
      accessToken: EJS.privateKey,
      template_params: {
        passcode: code, code,
        email: to, to_email: to, user_email: to, reply_to: to, to_name: to
      }
    })
  });
  if (!res.ok) {
    const t = await res.text().catch(() => "");
    throw new HttpsError("internal", "Письмо не отправилось: " + t.slice(0, 120));
  }
}

async function accountsOf(mailLow, withAuth) {
  const s = await db.collection("users").where("mailLow", "==", mailLow).limit(6).get();
  return s.docs
    .map((d) => ({ uid: d.id, ...d.data() }))
    .filter((u) => !u.isBot)
    .map((u) => {
      const base = {
        uid: u.uid, nick: u.nick || "", name: u.name || u.nick || "",
        photo: u.photo || "", verified: !!u.verified, banned: !!u.banned
      };
      if (withAuth) {
        base.authMail = u.authMail || ((u.nickLow || "") + "@kwora.id");
        base.mail = u.mail || "";
        base.mailLow = u.mailLow || "";
        base.nickLow = u.nickLow || "";
      }
      return base;
    });
}

/* поиск аккаунта при входе (до авторизации) — по почте или нику */
exports.loginLookup = onCall(async (req) => {
  const id = String((req.data && req.data.id) || "").trim().toLowerCase().replace(/^@/, "");
  if (!id) throw new HttpsError("invalid-argument", "Введите ник или почту.");

  if (id.includes("@") && id.includes(".")) {
    const accounts = await accountsOf(id, true);
    if (!accounts.length) throw new HttpsError("not-found", "Аккаунт с такой почтой не найден.");
    return { kind: "mail", accounts };
  }

  const q = await db.collection("users").where("nickLow", "==", id).limit(1).get();
  const u = q.empty ? null : q.docs[0].data();
  if (!u || u.isBot) throw new HttpsError("not-found", "Ник @" + id + " не найден.");
  return {
    kind: "nick",
    account: {
      uid: u.uid, nick: u.nick || "", name: u.name || u.nick || "",
      photo: u.photo || "", verified: !!u.verified, banned: !!u.banned,
      authMail: u.authMail || ((u.nickLow || "") + "@kwora.id"),
      mail: u.mail || "", mailLow: u.mailLow || "", nickLow: u.nickLow || ""
    }
  };
});

/* шаг 1: выслать код на почту */
exports.mailAuthStart = onCall(async (req) => {
  const mail = String((req.data && req.data.mail) || "").trim();
  const mailLow = mail.toLowerCase();
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(mailLow)) {
    throw new HttpsError("invalid-argument", "Почта написана неверно.");
  }
  const code = sixDigits();
  await db.collection("mailAuth").doc(mailLow).set({
    hash: sha(code), exp: Date.now() + 10 * 60 * 1000, tries: 0,
    at: FieldValue.serverTimestamp()
  });
  await sendCodeMail(mail, code);
  return { ok: true };
});

/* шаг 2: проверить код; action = list | login | reset */
exports.mailAuthConfirm = onCall(async (req) => {
  const d = req.data || {};
  const mailLow = String(d.mail || "").trim().toLowerCase();
  const code = String(d.code || "").trim();
  const action = String(d.action || "list");

  const ref = db.collection("mailAuth").doc(mailLow);
  const snap = await ref.get();
  if (!snap.exists) throw new HttpsError("failed-precondition", "Сначала запросите код.");
  const rec = snap.data();

  if (Date.now() > rec.exp) { await ref.delete().catch(() => {}); throw new HttpsError("deadline-exceeded", "Код истёк. Запросите новый."); }
  if ((rec.tries || 0) >= 5) { await ref.delete().catch(() => {}); throw new HttpsError("resource-exhausted", "Слишком много попыток. Запросите новый код."); }

  if (sha(code) !== rec.hash) {
    await ref.update({ tries: FieldValue.increment(1) }).catch(() => {});
    throw new HttpsError("permission-denied", "Неверный код.");
  }

  if (action === "list") {
    return { accounts: await accountsOf(mailLow) };
  }

  if (action === "register") {
    const nick = String(d.nick || "").trim().replace(/^@/, "");
    const low = nick.toLowerCase();
    const name = String(d.name || "").trim().slice(0, 32) || nick;
    if (!/^[a-z0-9_]{3,20}$/.test(low)) {
      throw new HttpsError("invalid-argument", "Ник: 3–20 знаков, латиница, цифры и _");
    }
    const exist = await accountsOf(mailLow);
    if (exist.length >= 4) {
      throw new HttpsError("resource-exhausted", "На эту почту уже 4 аккаунта.");
    }
    const taken = await db.collection("users").where("nickLow", "==", low).limit(1).get();
    if (!taken.empty) throw new HttpsError("already-exists", "Такой ник занят.");

    const user = await adminAuth.createUser({});
    await db.collection("users").doc(user.uid).set({
      uid: user.uid, nick, nickLow: low, name,
      mail: mailLow, mailLow,
      photo: "", bio: "", whoCanWrite: "all",
      verified: false, verifyAsked: false, badges: [], banned: false,
      createdAt: FieldValue.serverTimestamp()
    });
    await ref.delete().catch(() => {});
    const token = await adminAuth.createCustomToken(user.uid);
    return { token };
  }

  const uid = String(d.uid || "");
  const accs = await accountsOf(mailLow);
  const acc = accs.find((a) => a.uid === uid);
  if (!acc) throw new HttpsError("permission-denied", "Аккаунт не принадлежит этой почте.");
  if (acc.banned) throw new HttpsError("permission-denied", "Этот аккаунт заблокирован.");

  if (action === "reset") {
    const np = String(d.newPassword || "");
    if (np.length < 6) throw new HttpsError("invalid-argument", "Пароль короче 6 символов.");
    await adminAuth.updateUser(uid, { password: np });
  } else if (action !== "login") {
    throw new HttpsError("invalid-argument", "Неизвестное действие.");
  }

  await ref.delete().catch(() => {});
  const token = await adminAuth.createCustomToken(uid);
  return { token };
});

/* выдача значка "bot creator" за первого бота — сервером, после проверки */
exports.claimBotBadge = onCall(async (req) => {
  if (!req.auth || !req.auth.uid) {
    throw new HttpsError("unauthenticated", "Нужен вход в аккаунт.");
  }
  const uid = req.auth.uid;

  const own = await db.collection("users").where("botOwner", "==", uid).limit(1).get();
  if (own.empty) {
    throw new HttpsError("failed-precondition", "Сначала создайте бота.");
  }

  const cat = await db.collection("badges").get();
  const badge = cat.docs
    .map((d) => ({ id: d.id, ...d.data() }))
    .find((b) => String(b.name || "").trim().toLowerCase() === "bot creator");
  if (!badge) {
    throw new HttpsError("not-found", "Значок 'bot creator' не найден в каталоге.");
  }

  await db.collection("users").doc(uid).update({
    badges: FieldValue.arrayUnion(badge.id)
  });
  return { ok: true, badgeId: badge.id };
});

/* ---------- боты (без изменений) ---------- */
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
