const express = require("express");
const crypto = require("crypto");

const app = express();

/* =======================
   ZETTLE ACCESS TOKEN
======================= */

let cachedToken = null;
let tokenExpiresAt = 0;
let cachedPayPalToken = null;
let paypalTokenExpiresAt = 0;

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

async function getPayPalAccessToken() {
  const now = Date.now();
  if (cachedPayPalToken && now < paypalTokenExpiresAt - 60_000) {
    return cachedPayPalToken;
  }

  const clientId = process.env.PAYPAL_CLIENT_ID;
  const clientSecret = process.env.PAYPAL_CLIENT_SECRET;
  if (!clientId || !clientSecret) {
    throw new Error("Missing PAYPAL_CLIENT_ID or PAYPAL_CLIENT_SECRET");
  }

  const auth = Buffer.from(`${clientId}:${clientSecret}`).toString("base64");
  const res = await fetch(
    `https://api.${process.env.PAYPAL_ENV === "live" ? "paypal.com" : "sandbox.paypal.com"}/v1/oauth2/token`,
    {
      method: "POST",
      headers: {
        Authorization: `Basic ${auth}`,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: "grant_type=client_credentials",
    }
  );

  if (!res.ok) throw new Error(await res.text());

  const json = await res.json();
  cachedPayPalToken = json.access_token;
  paypalTokenExpiresAt = Date.now() + json.expires_in * 1000;
  return cachedPayPalToken;
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

app.post("/webhook", express.raw({ type: "*/*" }), async (req, res) => {
  const signingKey = process.env.ZETTLE_WEBHOOK_SIGNING_KEY;
  const signature = String(req.header("x-izettle-signature") || "").trim();

  const rawBody = req.body; // Buffer
 const paypalWebhookId = process.env.PAYPAL_WEBHOOK_ID;
  const paypalTransmissionId = req.header("paypal-transmission-id");
  const paypalTransmissionTime = req.header("paypal-transmission-time");
  const paypalCertUrl = req.header("paypal-cert-url");
  const paypalAuthAlgo = req.header("paypal-auth-algo");
  const paypalTransmissionSig = req.header("paypal-transmission-sig");

  const hasPayPalHeaders =
    paypalTransmissionId &&
    paypalTransmissionTime &&
    paypalCertUrl &&
    paypalAuthAlgo &&
    paypalTransmissionSig;

  if (hasPayPalHeaders && paypalWebhookId) {
    let body;
    try {
      body = JSON.parse(rawBody.toString("utf8"));
    } catch {
      return res.sendStatus(400);
    }

    try {
      const token = await getPayPalAccessToken();
      const verifyRes = await fetch(
        `https://api.${process.env.PAYPAL_ENV === "live" ? "paypal.com" : "sandbox.paypal.com"}/v1/notifications/verify-webhook-signature`,
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            auth_algo: paypalAuthAlgo,
            cert_url: paypalCertUrl,
            transmission_id: paypalTransmissionId,
            transmission_sig: paypalTransmissionSig,
            transmission_time: paypalTransmissionTime,
            webhook_id: paypalWebhookId,
            webhook_event: body,
          }),
        }
      );

      if (!verifyRes.ok) {
        console.warn("PayPal webhook verify failed:", await verifyRes.text());
        return res.sendStatus(401);
      }

      const verifyJson = await verifyRes.json();
      if (verifyJson.verification_status !== "SUCCESS") {
        console.warn("PayPal webhook signature invalid");
        return res.sendStatus(401);
      }
    } catch (error) {
      console.error("PayPal webhook verify error:", error.message);
      return res.sendStatus(500);
    }

    res.sendStatus(200);

    const products = body?.resource?.purchase_units?.flatMap(unit =>
      unit?.items?.map(item => ({
        name: item?.name || "Ukjent",
        quantity: Number(item?.quantity ?? 1) || 1,
      }))
    );

    if (products?.length) {
      for (const p of products) bump(p.name, p.quantity);
    } else {
      bump(body?.resource?.custom_id || "PayPal salg", 1);
    }

    sendToClients({
      type: "leaderboard",
      at: new Date().toISOString(),
      top: top20(),
    });

    console.log("PayPal webhook verified and processed");
    return;
  }

  if (!signingKey || !signature) return res.sendStatus(401);

  // Prøv nøkkel som tekst
  let expectedB64 = null;
  try {
    expectedB64 = crypto
      .createHmac("sha256", Buffer.from(signingKey, "base64"))
      .update(rawBody)
      .digest("hex");

  // Prøv nøkkel som base64 (fallback)
  let expectedB64 = null;
  try {
    expectedB64 = crypto
      .createHmac("sha256", Buffer.from(signingKey, "base64"))
      .update(rawBody)
      .digest("hex");
  } catch {
    expectedB64 = null;
  }

  const sig = signature.toLowerCase();
  const okText = sig === expectedText.toLowerCase();
  const okB64 = expectedB64 && sig === expectedB64.toLowerCase();
  
  if (!okB64 && !okText) {
    console.warn("Ugyldig webhook-signatur");
    console.warn("sig:", sig.slice(0, 12));
    console.warn("exp(text):", expectedText.slice(0, 12));
    if (expectedB64) console.warn("exp(b64):", expectedB64.slice(0, 12));
    return res.sendStatus(401);
  }

  // Signatur OK
  res.sendStatus(200);

  let body;
  try {
    body = JSON.parse(rawBody.toString("utf8"));
  } catch {
    return;
  }

  const products = body?.payload?.products || [];
  for (const p of products) {
    const name = p?.name || p?.productName || p?.variantName || "Ukjent";
    const qty = Number(p?.quantity ?? 1) || 1;
    bump(name, qty);
  }

  sendToClients({
    type: "leaderboard",
    at: new Date().toISOString(),
    top: top20(),
  });

  console.log(
    "Webhook verified and processed (",
    okB64 ? "base64-key" : "text-key",
    ")"
  );
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
