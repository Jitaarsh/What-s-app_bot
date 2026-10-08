// WhatsApp Cloud API echo bot. Only dependency: express. Needs Node 18+ (built-in fetch).
const express = require("express");
const crypto = require("crypto");

const {
  VERIFY_TOKEN,
  PHONE_NUMBER_ID,
  ACCESS_TOKEN,
  APP_SECRET, // optional but recommended: Meta app dashboard -> Settings -> Basic
  GRAPH_VERSION = "v26.0",
  PORT = 3000,
} = process.env;

for (const [k, v] of Object.entries({ VERIFY_TOKEN, PHONE_NUMBER_ID, ACCESS_TOKEN })) {
  if (!v) console.warn(`WARNING: env var ${k} is not set`);
}
if (!APP_SECRET) console.warn("WARNING: APP_SECRET not set, webhook signatures are NOT verified");

const app = express();

app.use((req, res, next) => {
  console.log(new Date().toISOString(), req.method, req.originalUrl);
  next();
});

// keep the raw body so we can check Meta's signature
app.use(express.json({ verify: (req, _res, buf) => { req.rawBody = buf; } }));

function validSignature(req) {
  if (!APP_SECRET) return true;
  const header = req.get("x-hub-signature-256") || "";
  const expected =
    "sha256=" + crypto.createHmac("sha256", APP_SECRET).update(req.rawBody || "").digest("hex");
  const a = Buffer.from(header);
  const b = Buffer.from(expected);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

// health check (Render + uptime pinger)
app.get("/", (_req, res) => res.send("ok"));

// webhook verification (Meta calls this once when you save the webhook URL)
app.get("/webhook", (req, res) => {
  if (req.query["hub.mode"] === "subscribe" && req.query["hub.verify_token"] === VERIFY_TOKEN) {
    return res.status(200).send(req.query["hub.challenge"]);
  }
  res.sendStatus(403);
});

// incoming messages
app.post("/webhook", (req, res) => {
  console.log("WEBHOOK BODY:", JSON.stringify(req.body));
  if (!validSignature(req)) return res.sendStatus(401);

  // always ack fast, Meta retries if you're slow
  res.sendStatus(200);

  const value = req.body?.entry?.[0]?.changes?.[0]?.value;
  const message = value?.messages?.[0];
  if (!message) return; // delivery/read status updates land here, ignore

  const from = message.from;
  const text = message.type === "text" ? message.text.body : null;
  console.log(`Message from ${from}: ${text ?? `[${message.type}]`}`);

  sendMessage(from, text ? `You said: ${text}` : `Got a ${message.type} message, I only read text for now.`)
    .catch((err) => console.error("send failed:", err.message));
});

async function sendMessage(to, body) {
  const r = await fetch(`https://graph.facebook.com/${GRAPH_VERSION}/${PHONE_NUMBER_ID}/messages`, {
    method: "POST",
    headers: { Authorization: `Bearer ${ACCESS_TOKEN}`, "Content-Type": "application/json" },
    body: JSON.stringify({ messaging_product: "whatsapp", to, type: "text", text: { body } }),
  });
  if (!r.ok) throw new Error(`Graph API ${r.status}: ${await r.text()}`);
}

app.listen(PORT, "0.0.0.0", () => console.log(`Listening on ${PORT}`));