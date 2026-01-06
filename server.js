const express = require("express");
const crypto = require("crypto");

let cachedToken = null;
let tokenExpiresAtMs = 0;

async function getAccessToken() {
  const now = Date.now();
  if (cachedToken && now < tokenExpiresAtMs - 60_000) return cachedToken; // 60 sek buffer

  const clientId = process.env.ZETTLE_CLIENT_ID;
  const apiKey = process.env.ZETTLE_API_KEY;

  if (!clientId || !apiKey) {
    throw new Error("Mangler ZETTLE_CLIENT_ID eller ZETTLE_API_KEY");
  }

  const body = new URLSearchParams();
  body.set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer");
  body.set("client_id", clientId);
  body.set("assertion", apiKey);

  const res = await fetch("https://oauth.zettle.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });

  if (!res.ok) {
    throw new Error(`Token-feil ${res.status}: ${await res.text()}`);
  }

  const json = await res.json();
  cachedToken = json.access_token;
  tokenExpiresAtMs = Date.now() + (Number(json.expires_in) || 0) * 1000;
  return cachedToken;
}

const app = express();


// gjør public/ tilgjengelig
app.use(express.static("public"));
// app.use(express.json()); // midlertidig av

// ---- LIVE EVENTS (SSE) ----
let clients = [];
const leaderboard = new Map();

function bump(name, qty) {
  const prev = leaderboard.get(name) || 0;
  leaderboard.set(name, prev + qty);
}

function top20() {
  return Array.from(leaderboard.entries())
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 20);
}


function sendToClients(data) {
  const msg = `data: ${JSON.stringify(data)}\n\n`;
  clients.forEach((res) => res.write(msg));
}

app.get("/events", (req, res) => {
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");

  clients.push(res);

  sendToClients({ type: "connected", at: new Date().toISOString() });

  req.on("close", () => {
    clients = clients.filter((c) => c !== res);
  });
});

// ---- WEBHOOK ----
let purchaseEvents = 0;

app.post("/webhook", express.raw({ type: "*/*" }), (req, res) => {
const signingKey = process.env.ZETTLE_WEBHOOK_SIGNING_KEY;
if (!signingKey) return res.sendStatus(500);

const receivedSignature = String(req.header("X-iZettle-Signature") || "").trim();
if (!receivedSignature) return res.sendStatus(401);

// req.body er raw bytes (Buffer)
const rawBody = req.body;

// 1) HMAC med signingKey som tekst
const expectedHexTextKey = crypto
  .createHmac("sha256", signingKey)
  .update(rawBody)
  .digest("hex");

// 2) HMAC med signingKey base64-dekodet
let expectedHexB64Key = null;
try {
  const keyBuf = Buffer.from(signingKey, "base64");
  expectedHexB64Key = crypto
    .createHmac("sha256", keyBuf)
    .update(rawBody)
    .digest("hex");
} catch {}

const recvLower = receivedSignature.toLowerCase();

const ok =
  recvLower === expectedHexTextKey.toLowerCase() ||
  (expectedHexB64Key && recvLower === expectedHexB64Key.toLowerCase());

if (!ok) {
  console.warn("Ugyldig webhook-signatur");
  console.warn("Sig header starts:", receivedSignature.slice(0, 12));
  console.warn("Expected(text key) starts:", expectedHexTextKey.slice(0, 12));
  if (expectedHexB64Key) {
    console.warn("Expected(b64 key) starts:", expectedHexB64Key.slice(0, 12));
  }
  return res.sendStatus(401);
}

const raw = req.body; // dette er raw tekst (viktig)

// Beregn både hex og base64 (Zettle kan bruke base64)
const hmac = crypto.createHmac("sha256", signingKey).update(raw, "utf8");
const expectedHex = hmac.digest("hex");

// må lage hmac på nytt for base64 (digest() "tømmer" objektet)
const expectedBase64 = crypto
  .createHmac("sha256", signingKey)
  .update(raw, "utf8")
  .digest("base64");

// Noen systemer sender base64 uten padding "=". Normaliser begge veier.
const recv = String(receivedSignature).trim();
const recvNoPad = recv.replace(/=+$/, "");
const expB64NoPad = expectedBase64.replace(/=+$/, "");

// timing-safe compare (bare hvis samme lengde)
function safeEqual(a, b) {
  const ba = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

  // Signatur OK – fortsett
  res.sendStatus(200);

let bodyStr = rawBody.toString("utf8");
let body;

try {
  body = JSON.parse(bodyStr);
} catch {
  return;
}

if (typeof body?.payload === "string") {
  try {
    body.payload = JSON.parse(body.payload);
  } catch {
    return;
  }
}
  if (typeof body?.payload === "string") {
    try {
      body.payload = JSON.parse(body.payload);
    } catch {
      return;
    }
  }

  const products = body?.payload?.products || [];

  for (const p of products) {
    const name =
      p?.name ||
      p?.productName ||
      p?.variantName ||
      "Ukjent produkt";

    const qty = Number(p?.quantity ?? 1) || 1;
    bump(name, qty);
  }

  sendToClients({
    type: "leaderboard",
    at: new Date().toISOString(),
    top: top20(),
  });

  console.log("Webhook verified and processed");
});

// ---- TEST: purchases count ----
app.get("/purchases-count", async (req, res) => {
  try {
    const token = await getAccessToken();
    if (!token) {
      return res.status(500).send("Mangler ZETTLE_ACCESS_TOKEN");
    }

    const response = await fetch(
      "https://purchase.izettle.com/purchases/v2",
      {
        headers: { Authorization: `Bearer ${token}` },
      }
    );

    if (!response.ok) {
      const text = await response.text();
      return res
        .status(response.status)
        .send(`Zettle-feil ${response.status}: ${text}`);
    }

    const data = await response.json();

    const count = Array.isArray(data)
      ? data.length
      : Array.isArray(data.purchases)
      ? data.purchases.length
      : 0;

    res.send(`Antall salg hentet: ${count}`);
  } catch (err) {
    res.status(500).send(`Server-feil: ${err.message}`);
  }
});

// ---- START SERVER ----
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Server kjører på port ${PORT}`);
});

