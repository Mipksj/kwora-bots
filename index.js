/**
 * Kwora server: боты + почтовая авторизация (забыл пароль / вход без пароля).
 */
const crypto = require("crypto");
const { onDocumentCreated } = require("firebase-functions/v2/firestore");
const { onCall, HttpsError } = require("firebase-functions/v2/https");
const { initializeApp } = require("firebase-admin/app");
const { getFirestore, FieldValue } = require("firebase-admin/firestore");
const { getAuth } = require("firebase-admin/auth");
const { getMessaging } = require("firebase-admin/messaging");

initializeApp();
const db = getFirestore();
const adminAuth = getAuth();
const fcm = getMessaging();

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

/* шаг 1: выслать код на почту */
exports.mailAuthStart = onCall(async (req) => {
  const mail = String((req.data && req.data.mail) || "").trim();
  const mailLow = mail.toLowerCase();
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(mailLow)) {
    throw new HttpsError("invalid-argument", "Почта написана неверно.");
  }
  const prev = await db.collection("mailAuth").doc(mailLow).get();
  if (prev.exists && prev.data().at && (Date.now() - prev.data().at.toMillis() < 60000)) {
    throw new HttpsError("resource-exhausted", "Код уже отправлен. Подождите минуту.");
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

        const lockRef = db.collection("nicks").doc(low);
    try {
      await db.runTransaction(async (t) => {
        const l = await t.get(lockRef);
        if (l.exists) throw new HttpsError("already-exists", "Такой ник занят.");
        t.set(lockRef, { at: Date.now() });
      });
    } catch (e) {
      if (e instanceof HttpsError) throw e;
      throw new HttpsError("internal", "Не получилось занять ник.");
    }

    let user;
    try { user = await adminAuth.createUser({}); }
    catch (e) { await lockRef.delete().catch(() => {}); throw new HttpsError("internal", "Не получилось создать аккаунт."); }
    await db.collection("users").doc(user.uid).set({
      uid: user.uid, nick, nickLow: low, name,
      mail: mailLow, mailLow,
      photo: "", bio: "", whoCanWrite: "all",
      verified: false, verifyAsked: false, badges: [], banned: false,
      createdAt: FieldValue.serverTimestamp()
    });
    {
      const pw = String((req.data && req.data.newPassword) || "");
      if (pw) {
        if (!PASS_RE.test(pw)) throw new HttpsError("invalid-argument", "Пароль: минимум 6 символов, латинские буквы и цифры.");
        await db.collection("secrets").doc(user.uid).set({ passHash: passHash(user.uid, pw), at: Date.now() });
      }
    }
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
    if (!PASS_RE.test(np)) throw new HttpsError("invalid-argument", "Пароль: минимум 6 символов, латинские буквы и цифры.");
    await db.collection("secrets").doc(uid)
      .set({ passHash: passHash(uid, np), at: Date.now() }, { merge: true });
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


/* ---------- ПУШ-УВЕДОМЛЕНИЯ о новых сообщениях ---------- */
const APP_URL = "https://kwora.ru/";

exports.pushOnMessage = onDocumentCreated("chats/{chat}/messages/{msg}", async (event) => {
  const m = event.data ? event.data.data() : null;
  if (!m || m.sys) return;

  const chatId = event.params.chat;
  const cs = await db.collection("chats").doc(chatId).get();
  if (!cs.exists) return;
  const c = cs.data();

  const to = (c.members || []).filter((u) => u && u !== m.from);
  if (!to.length) return;

  const snaps = await db.getAll(...to.map((u) => db.collection("users").doc(u)));
  const tokens = [];
  const ownerOf = {};
  snaps.forEach((d) => {
    const arr = (d.data() || {}).fcmTokens || [];
    arr.forEach((t) => { if (t && !ownerOf[t]) { tokens.push(t); ownerOf[t] = d.id; } });
  });
  if (!tokens.length) return;

  const info = (c.info || {})[m.from] || {};
  const sender = info.name || info.nick || "Kwora";
  const what = m.text ? String(m.text).slice(0, 120)
    : (m.img ? "Фото" : (m.voice ? "Голосовое" : (m.video ? "Видео"
    : (m.poll ? "Опрос: " + String((m.poll.q || "")).slice(0, 80)
    : (m.contact ? "Контакт" : "Сообщение")))));
  const title = c.type === "group" ? (c.name || "Группа") : sender;
  const body = c.type === "group" ? sender + ": " + what : what;

  const res = await fcm.sendEachForMulticast({
    tokens,
    data: { title, body, url: APP_URL, chat: chatId },
    webpush: { headers: { Urgency: "high" }, fcmOptions: { link: APP_URL } }
  });

  const dead = [];
  res.responses.forEach((r, i) => {
    if (!r.success) {
      const code = (r.error && r.error.code) || "";
      if (code.includes("registration-token-not-registered") || code.includes("invalid-argument")) dead.push(tokens[i]);
    }
  });
  await Promise.all(dead.map((t) =>
    db.collection("users").doc(ownerOf[t]).update({ fcmTokens: FieldValue.arrayRemove(t) }).catch(() => {})
  ));
});


/* ---------- ПУШ О ВХОДЯЩЕМ ЗВОНКЕ ---------- */
exports.pushOnCall = onDocumentCreated("calls/{call}", async (event) => {
  const d = event.data ? event.data.data() : null;
  if (!d || !d.to || !d.from) return;
  if (d.state && d.state !== "ringing") return;

  const [toSnap, fromSnap] = await Promise.all([
    db.collection("users").doc(d.to).get(),
    db.collection("users").doc(d.from).get()
  ]);
  const tokens = ((toSnap.data() || {}).fcmTokens || []).filter(Boolean);
  if (!tokens.length) return;

  const fromU = fromSnap.data() || {};
  const caller = fromU.name || fromU.nick || "Kwora";
  const kind = d.video ? "Видеозвонок" : "Звонок";

  const res = await fcm.sendEachForMulticast({
    tokens,
    data: {
      type: "call",
      title: caller,
      body: kind + "…",
      url: APP_URL,
      callId: event.params.call
    },
    android: { priority: "high" },
    webpush: {
      headers: { Urgency: "high", TTL: "30" },
      fcmOptions: { link: APP_URL }
    }
  });

  const dead = [];
  res.responses.forEach((r, i) => {
    if (!r.success) {
      const code = (r.error && r.error.code) || "";
      if (code.includes("registration-token-not-registered") || code.includes("invalid-argument")) dead.push(tokens[i]);
    }
  });
  await Promise.all(dead.map((t) =>
    db.collection("users").doc(d.to).update({ fcmTokens: FieldValue.arrayRemove(t) }).catch(() => {})
  ));
});


/* ---------- смена почты по коду ---------- */
exports.changeMyMail = onCall(async (req) => {
  const uid = req.auth && req.auth.uid;
  if (!uid) throw new HttpsError("unauthenticated", "Нужен вход.");
  const mail = String((req.data && req.data.mail) || "").trim();
  const code = String((req.data && req.data.code) || "").trim();
  const low = mail.toLowerCase();
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(mail)) throw new HttpsError("invalid-argument", "Почта неверна.");
  if (!/^\d{6}$/.test(code)) throw new HttpsError("invalid-argument", "Код неверен.");

  // проверка кода из mailAuth/{low}
  const ref = db.collection("mailAuth").doc(low);
  const snap = await ref.get();
  if (!snap.exists) throw new HttpsError("not-found", "Сначала запросите код.");
  const d = snap.data();
  if (Date.now() > (d.exp || 0)) { await ref.delete().catch(() => {}); throw new HttpsError("deadline-exceeded", "Код истёк."); }
  if ((d.tries || 0) >= 5) { await ref.delete().catch(() => {}); throw new HttpsError("resource-exhausted", "Слишком много попыток."); }
  if (sha(code) !== d.hash) { await ref.update({ tries: (d.tries || 0) + 1 }).catch(() => {}); throw new HttpsError("permission-denied", "Неверный код."); }

  // лимит аккаунтов на почту
  const q = await db.collection("users").where("mailLow", "==", low).get();
  const others = q.docs.filter((x) => x.id !== uid).length;
  if (others >= 4) throw new HttpsError("already-exists", "На эту почту уже 4 аккаунта.");

  await db.collection("users").doc(uid).update({ mail, mailLow: low });
  await ref.delete().catch(() => {});
  return { ok: true };
});


/* ---------- ПАРОЛЬНЫЙ ВХОД ---------- */
const PASS_RE = /^(?=.*[A-Za-z])(?=.*\d)[\x21-\x7E]{6,64}$/;
const passHash = (uid, pass) => crypto.createHash("sha256").update(uid + "|" + pass).digest("hex");

exports.passLogin = onCall(async (req) => {
  const mail = String((req.data && req.data.mail) || "").trim();
  const password = String((req.data && req.data.password) || "");
  const pickUid = String((req.data && req.data.uid) || "");
  const low = mail.toLowerCase();
  if (!low || !password) throw new HttpsError("invalid-argument", "Почта и пароль обязательны.");

  const q = await db.collection("users").where("mailLow", "==", low).get();
  if (q.empty) throw new HttpsError("not-found", "Аккаунтов с этой почтой нет.");

  const matched = [];
  for (const d of q.docs) {
    const sec = await db.collection("secrets").doc(d.id).get();
    const h = sec.exists ? sec.data().passHash : null;
    if (h && h === passHash(d.id, password)) matched.push(d);
  }
  if (!matched.length) throw new HttpsError("permission-denied", "Неверный пароль (или для аккаунта пароль ещё не установлен — войдите через «Забыли пароль?»).");

  let target = matched[0];
  if (pickUid) {
    target = matched.find((d) => d.id === pickUid);
    if (!target) throw new HttpsError("permission-denied", "Неверный выбор аккаунта.");
  } else if (matched.length > 1) {
    return {
      pick: true,
      accounts: matched.map((d) => { const u = d.data(); return { uid: d.id, nick: u.nick, name: u.name || "", photo: u.photo || "" }; })
    };
  }
  if (target.data().banned) throw new HttpsError("permission-denied", "Аккаунт заблокирован.");
  const token = await adminAuth.createCustomToken(target.id);
  return { token, uid: target.id };
});

exports.setMyPass = onCall(async (req) => {
  const uid = req.auth && req.auth.uid;
  if (!uid) throw new HttpsError("unauthenticated", "Нужен вход.");
  const password = String((req.data && req.data.password) || "");
  if (!PASS_RE.test(password)) throw new HttpsError("invalid-argument", "Пароль: минимум 6 символов, латинские буквы и цифры.");
  await db.collection("secrets").doc(uid).set({ passHash: passHash(uid, password), at: Date.now() }, { merge: true });
  return { ok: true };
});

exports.changeMyPass = onCall(async (req) => {
  const uid = req.auth && req.auth.uid;
  if (!uid) throw new HttpsError("unauthenticated", "Нужен вход.");
  const oldPassword = String((req.data && req.data.oldPassword) || "");
  const newPassword = String((req.data && req.data.newPassword) || "");
  if (!PASS_RE.test(newPassword)) {
    throw new HttpsError("invalid-argument", "Новый пароль: минимум 6 символов, латинские буквы и цифры.");
  }
  const sec = await db.collection("secrets").doc(uid).get();
  const cur = sec.exists ? sec.data().passHash : null;
  if (!cur) throw new HttpsError("failed-precondition", "Пароль ещё не установлен.");
  if (cur !== passHash(uid, oldPassword)) {
    throw new HttpsError("permission-denied", "Текущий пароль неверен.");
  }
  await db.collection("secrets").doc(uid)
    .set({ passHash: passHash(uid, newPassword), at: Date.now() }, { merge: true });
  return { ok: true };
});

exports.hasPass = onCall(async (req) => {
  const uid = req.auth && req.auth.uid;
  if (!uid) throw new HttpsError("unauthenticated", "Нужен вход.");
  const sec = await db.collection("secrets").doc(uid).get();
  return { has: !!(sec.exists && sec.data().passHash) };
});
