const express = require("express");
const fetch = require("node-fetch");

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
const fetch = require("node-fetch");

let cachedToken = null;
let tokenExpiresAtMs = 0;

async function getAccessToken() {
  const now = Date.now();
  if (cachedToken && now < tokenExpiresAtMs - 60_000) return cachedToken; // 60s buffer

  const clientId = process.env.ZETTLE_CLIENT_ID;
  const apiKey = process.env.ZETTLE_API_KEY;
  if (!clientId || !apiKey) throw new Error("Mangler ZETTLE_CLIENT_ID eller ZETTLE_API_KEY");

  const body = new URLSearchParams();
  body.set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer");
  body.set("client_id", clientId);
  body.set("assertion", apiKey);

  const res = await fetch("https://oauth.zettle.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });

  if (!res.ok) throw new Error(`Token-feil ${res.status}: ${await res.text()}`);

  const json = await res.json();
  cachedToken = json.access_token;
  tokenExpiresAtMs = Date.now() + (Number(json.expires_in) || 0) * 1000;
  return cachedToken;
}

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

app.post("/webhook", express.text({ type: "*/*" }), (req, res) => {
  res.sendStatus(200);

  let body = req.body;

  // 1) Parse body hvis den er tekst
  if (typeof body === "string") {
    try {
      body = JSON.parse(body);
    } catch (e) {
      console.log("Kunne ikke parse body");
      return;
    }
  }

  // 2) Parse payload hvis payload er tekst
  if (typeof body?.payload === "string") {
    try {
      body.payload = JSON.parse(body.payload);
    } catch (e) {
      console.log("Kunne ikke parse payload");
      return;
    }
  }

  // 3) Hent produkter direkte fra webhook-payload
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

  // 4) Send oppdatert leaderboard live til nettsiden
  sendToClients({
    type: "leaderboard",
    at: new Date().toISOString(),
    top: top20(),
  });
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

