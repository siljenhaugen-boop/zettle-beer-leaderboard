const express = require("express");
const crypto = require("crypto");

const app = express();

/* =======================
   ZETTLE ACCESS TOKEN
======================= */

let cachedToken = null;
let tokenExpiresAt = 0;

async function getAccessToken() {
  const now = Date.now();
  if (cachedToken && now < tokenExpiresAt - 60_000) return cachedToken;

  const body = new URLSearchParams({
    grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
    client_id: process.env.ZETTLE_CLIENT_ID,
    assertion: process.env.ZETTLE_API_KEY,
  });

  const res = await fetch("https://oauth.zettle.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });

  if (!res.ok) throw new Error(await res.text());

  const json = await res.json();
  cachedToken = json.access_token;
  tokenExpiresAt = Date.now() + json.expires_in * 1000;
  return cachedToken;
}

/* =======================
   STATIC + SSE
======================= */

app.use(express.static("public"));

let clients = [];
const leaderboard = new Map();

function bump(name, qty) {
  leaderboard.set(name, (leaderboard.get(name) || 0) + qty);
}

function top20() {
  return [...leaderboard.entries()]
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 20);
}

function sendToClients(data) {
  const msg = `data: ${JSON.stringify(data)}\n\n`;
  clients.forEach(c => c.write(msg));
}

app.get("/events", (req, res) => {
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  clients.push(res);

  req.on("close", () => {
    clients = clients.filter(c => c !== res);
  });
});

/* =======================
   WEBHOOK (RAW BODY)
======================= */

app.post("/webhook", express.raw({ type: "*/*" }), (req, res) => {
const signingKey = process.env.ZETTLE_WEBHOOK_SIGNING_KEY;
const signature = String(req.header("X-iZettle-Signature") || "").trim();
if (!signingKey || !signature) return res.sendStatus(401);

const rawBody = req.body; // Buffer (raw bytes)

// 1) HMAC med signingKey som TEKST
const expectedText = crypto
  .createHmac("sha256", signingKey)
  .update(rawBody)
  .digest("hex");

// 2) HMAC med signingKey som BASE64-dekodet
let expectedB64 = null;
try {
  const keyBuf = Buffer.from(signingKey, "base64");
  expectedB64 = crypto
    .createHmac("sha256", keyBuf)
    .update(rawBody)
    .digest("hex");
} catch {}

const sig = signature.toLowerCase();
const ok =
  sig === expectedText.toLowerCase() ||
  (expectedB64 && sig === expectedB64.toLowerCase());

if (!ok) {
  console.warn("Ugyldig webhook-signatur");
  console.warn("sig:", sig.slice(0, 12));
  console.warn("exp(text):", expectedText.slice(0, 12));
  if (expectedB64) console.warn("exp(b64):", expectedB64.slice(0, 12));
  return res.sendStatus(401);
}

// Signatur OK – fortsett
  res.sendStatus(200);

  let body;
  try {
    body = JSON.parse(req.body.toString("utf8"));
  } catch {
    return;
  }

  const products = body?.payload?.products || [];
  for (const p of products) {
    bump(
      p.name || p.productName || p.variantName || "Ukjent",
      Number(p.quantity || 1)
    );
  }

  sendToClients({
    type: "leaderboard",
    at: new Date().toISOString(),
    top: top20(),
  });

  console.log("Webhook verified and processed");
});

/* =======================
   TEST ENDPOINT
======================= */

app.get("/purchases-count", async (req, res) => {
  try {
    const token = await getAccessToken();
    const r = await fetch("https://purchase.izettle.com/purchases/v2", {
      headers: { Authorization: `Bearer ${token}` },
    });
    const j = await r.json();
    res.send(`Antall salg hentet: ${j?.purchases?.length || 0}`);
  } catch (e) {
    res.status(500).send(e.message);
  }
});

/* =======================
   START
======================= */

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Server kjører på port", PORT));
