// Netlify Function: sign + forward the quote form submission to the Frankly
// Sales Agent pipeline.
//
// Browser POSTs to /.netlify/functions/calculator-webhook (same-origin, no
// CORS, no secret exposed in client JS). This function reads the shared
// secret from Netlify env vars (CALCULATOR_WEBHOOK_SECRET), HMAC-signs the
// body, and forwards to the pipeline's /webhooks/calculator-quote endpoint.
//
// Why a proxy? Putting HMAC signing in browser JS would leak the secret to
// anyone viewing page source. With this proxy, the secret stays on Netlify's
// servers (set the env var there, same value as on Render).
//
// Setup checklist:
//   1. On Netlify: Site → Site settings → Environment variables → add
//      CALCULATOR_WEBHOOK_SECRET (same value as on Render).
//   2. Deploy this file with the site — Netlify auto-detects functions in
//      `netlify/functions/`.
//   3. quote.html POSTs to '/.netlify/functions/calculator-webhook'.

const PIPELINE_URL =
  "https://frankly-pipeline.onrender.com/webhooks/calculator-quote";

// Map the quote.html "≤50 / ≤150 / ≤400 / 400+" transaction band to a single
// integer the pricing engine can recommend a tier from. We pick the band's
// upper bound — conservative for the lead (slightly more expensive tier than
// the midpoint would have picked), which matches Shay's preference of
// over-quoting at intake and adjusting down on the call.
function parseTxnBand(band) {
  if (!band) return null;
  const cleaned = String(band).replace(/\s/g, "");
  if (/^≤?50$/.test(cleaned)) return 50;
  if (/^≤?150$/.test(cleaned)) return 150;
  if (/^≤?400$/.test(cleaned)) return 400;
  if (/400\+/.test(cleaned)) return 500;
  // If the form ever sends a raw number, accept it.
  const n = parseInt(cleaned, 10);
  return Number.isFinite(n) && n > 0 ? n : null;
}

// Heuristic: the quote.html intake form doesn't have an explicit tier picker
// (the user just picks services + answers questions). We let the pipeline's
// build_quote engine recommend a tier from monthly_transactions when no plan
// is sent — that's the cleanest mapping.

// Map the boolean-ish HST/payroll/catchup signals into the structured
// add_ons object the pipeline expects.
function buildAddOns(body) {
  const addOns = {};
  // HST status: "Yes / registered" → true; everything else → false.
  if (body.hst_status && /^yes/i.test(body.hst_status)) addOns.hst = true;
  // Payroll: any selection other than "No employees" → enable + parse headcount.
  const hasPayroll =
    body.employees_subs && !/^no/i.test(body.employees_subs);
  if (hasPayroll) {
    addOns.payroll = true;
    // headcount_band is something like "1-5", "6-10", "11+". Pick midpoint.
    const band = body.headcount_band || "";
    let emp = 0;
    if (/^1-5$/.test(band)) emp = 3;
    else if (/^6-10$/.test(band)) emp = 8;
    else if (/^11/.test(band)) emp = 12;
    addOns.employees = emp;
  }
  // Catchup months: similar band → integer.
  const cu = body.months_behind_band || "";
  if (cu && !/^no/i.test(cu) && !/^0/.test(cu)) {
    if (/^1-3/.test(cu)) addOns.catchup_months = 3;
    else if (/^4-6/.test(cu)) addOns.catchup_months = 6;
    else if (/^7-12/.test(cu)) addOns.catchup_months = 12;
    else if (/^>?12/.test(cu)) addOns.catchup_months = 18;
  }
  // Books state implies the lead needs setup.
  if (
    body.books_state &&
    /no|starting|none/i.test(body.books_state)
  ) {
    addOns.setup = true;
  }
  return addOns;
}

exports.handler = async (event) => {
  // Only POST is supported. GET / OPTIONS get a friendly 405.
  if (event.httpMethod !== "POST") {
    return {
      statusCode: 405,
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ ok: false, error: "POST only" }),
    };
  }

  const secret = process.env.CALCULATOR_WEBHOOK_SECRET;
  if (!secret) {
    console.error(
      "calculator-webhook: CALCULATOR_WEBHOOK_SECRET not set on Netlify."
    );
    return {
      statusCode: 500,
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ ok: false, error: "server not configured" }),
    };
  }

  let raw;
  try {
    raw = JSON.parse(event.body || "{}");
  } catch (e) {
    return {
      statusCode: 400,
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ ok: false, error: "malformed JSON" }),
    };
  }
  if (!raw.email || !raw.email.includes("@")) {
    return {
      statusCode: 400,
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ ok: false, error: "email is required" }),
    };
  }

  // Translate quote.html's flat form fields into the pipeline's payload schema.
  const txn = parseTxnBand(raw.monthly_transactions);
  const payload = {
    email: String(raw.email).trim(),
    first_name: (raw.first_name || "").trim(),
    last_name: (raw.last_name || "").trim(),
    phone: (raw.phone || "").trim(),
    business_name: (raw.business_name || "").trim(),
    business_structure: (raw.business_structure || "").trim() || null,
    monthly_transactions: txn,
    add_ons: buildAddOns(raw),
    // calculator_url helps the agent debug where a lead came from later.
    calculator_url:
      event.headers.referer || event.headers.Referer || "quote.html",
  };
  // The screenshot calculator also passes `plan` directly when the lead
  // explicitly picks a tier — forward that through if present.
  if (raw.plan) payload.plan = raw.plan;
  // Same for explicit booking intent + meeting time, used by skill_20 to
  // confirm-the-booking instead of asking for one.
  if (raw.booked_meeting) payload.booked_meeting = true;
  if (raw.meeting_starts_at) payload.meeting_starts_at = raw.meeting_starts_at;

  const body = JSON.stringify(payload);
  const ts = Math.floor(Date.now() / 1000).toString();

  // HMAC-SHA256 using Node's built-in crypto — no extra deps.
  const crypto = require("crypto");
  const signed = `${ts}.${body}`;
  const sig = crypto
    .createHmac("sha256", secret)
    .update(signed)
    .digest("base64");
  const signature = `hmac;1;${ts};${sig}`;

  try {
    const upstream = await fetch(PIPELINE_URL, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-frankly-signature": signature,
      },
      body,
    });
    const text = await upstream.text();
    return {
      statusCode: upstream.status,
      headers: { "content-type": "application/json" },
      // Pass through the pipeline's response so the browser can show errors.
      body: text || JSON.stringify({ ok: upstream.ok }),
    };
  } catch (e) {
    console.error("calculator-webhook: forward failed", e);
    return {
      statusCode: 502,
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        ok: false,
        error: "pipeline forward failed: " + (e && e.message),
      }),
    };
  }
};
