const API_BASE = process.env.API_BASE || "http://127.0.0.1:8787";
const TOKEN = process.env.TOKEN || "";

async function request(path) {
  const headers = { accept: "application/json" };
  if (TOKEN) {
    headers.authorization = `Bearer ${TOKEN}`;
  }
  const response = await fetch(`${API_BASE}${path}`, { headers });
  let body = null;
  try {
    body = await response.json();
  } catch {
    body = await response.text();
  }
  return { response, body };
}

async function run() {
  if (!TOKEN) {
    console.error("TOKEN is required for smoke-link.");
    process.exit(1);
  }

  const me = await request("/api/me");
  console.log("GET /api/me", me.response.status, me.body);
  if (!me.response.ok) process.exit(1);

  const identities = await request("/api/me/identities");
  console.log("GET /api/me/identities", identities.response.status, identities.body);
  if (!identities.response.ok) process.exit(1);
}

run().catch((err) => {
  console.error(err);
  process.exit(1);
});
