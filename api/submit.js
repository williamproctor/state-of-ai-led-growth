import { createHash } from 'node:crypto';

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const IP_HASH_SALT = process.env.IP_HASH_SALT || '';

const CONTACT_FIELDS = new Set([
  'first_name',
  'last_name',
  'email',
  'position',
  'optin',
  'advisor_optin',
]);

const META_FIELDS = new Set([
  'website', // honeypot
  'utm_source',
  'utm_medium',
  'utm_campaign',
  'utm_term',
  'utm_content',
  'referrer',
]);

function isValidEmail(value) {
  if (typeof value !== 'string') return false;
  const trimmed = value.trim();
  if (trimmed.length < 5 || trimmed.length > 254) return false;
  // Pragmatic email check; full RFC 5322 is overkill.
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(trimmed);
}

function hashIp(ip) {
  if (!ip) return null;
  return createHash('sha256').update(ip + IP_HASH_SALT).digest('hex');
}

function getClientIp(req) {
  const xff = req.headers['x-forwarded-for'];
  if (typeof xff === 'string' && xff.length > 0) {
    return xff.split(',')[0].trim();
  }
  return req.socket?.remoteAddress || null;
}

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ error: 'Method not allowed' });
  }

  if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
    console.error('Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY');
    return res.status(500).json({ error: 'Server not configured' });
  }

  let body = req.body;
  if (typeof body === 'string') {
    try { body = JSON.parse(body); } catch { return res.status(400).json({ error: 'Invalid JSON' }); }
  }
  if (!body || typeof body !== 'object') {
    return res.status(400).json({ error: 'Invalid payload' });
  }

  // Honeypot: real users won't fill the hidden "website" field.
  // Bots that auto-fill all inputs will. We accept the submission silently
  // (return 200) so spammers don't learn the trigger, but we never insert it.
  const honeypotPass = !body.website || String(body.website).trim() === '';

  if (!isValidEmail(body.email)) {
    return res.status(400).json({ error: 'A valid work email is required.' });
  }

  if (typeof body.first_name !== 'string' || body.first_name.trim().length === 0) {
    return res.status(400).json({ error: 'First name is required.' });
  }

  if (typeof body.position !== 'string' || body.position.trim().length === 0) {
    return res.status(400).json({ error: 'Title / position is required.' });
  }

  // Split form data into contact, meta, and survey-answers buckets.
  const answers = {};
  const utm = {};
  for (const [key, value] of Object.entries(body)) {
    if (CONTACT_FIELDS.has(key)) continue;
    if (META_FIELDS.has(key)) {
      if (key.startsWith('utm_') && value) utm[key] = String(value).slice(0, 256);
      continue;
    }
    // Skip fields the client adds for tracking but we don't want in answers
    if (key === 'submitted_at') continue;
    // Everything else is a survey answer (q1..q27 + *-other inputs)
    answers[key] = value;
  }

  // If honeypot tripped, pretend success but don't write to DB.
  if (!honeypotPass) {
    console.warn('Honeypot tripped from', getClientIp(req));
    return res.status(200).json({ ok: true });
  }

  const ip = getClientIp(req);
  const userAgent = req.headers['user-agent'] || null;

  const row = {
    email: body.email.trim().toLowerCase(),
    first_name: body.first_name?.trim() || null,
    last_name: typeof body.last_name === 'string' ? body.last_name.trim() || null : null,
    position: body.position.trim(),
    optin_report: body.optin === 'yes' || body.optin === true,
    optin_advisor: body.advisor_optin === 'yes' || body.advisor_optin === true,
    answers,
    utm: Object.keys(utm).length > 0 ? utm : null,
    referrer: typeof body.referrer === 'string' ? body.referrer.slice(0, 1024) : null,
    ip_hash: hashIp(ip),
    user_agent: userAgent ? userAgent.slice(0, 512) : null,
    honeypot_pass: true,
  };

  const upsertUrl = `${SUPABASE_URL}/rest/v1/responses?on_conflict=email`;

  let response;
  try {
    response = await fetch(upsertUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        apikey: SUPABASE_SERVICE_ROLE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
        // Upsert: if this email already submitted, update their row instead of erroring.
        // Remove `resolution=merge-duplicates` if you want duplicate emails to fail loudly.
        Prefer: 'resolution=merge-duplicates,return=minimal',
      },
      body: JSON.stringify(row),
    });
  } catch (err) {
    console.error('Supabase fetch failed', err);
    return res.status(502).json({ error: 'Could not reach the database. Please try again.' });
  }

  if (!response.ok) {
    const text = await response.text().catch(() => '');
    console.error('Supabase insert failed', response.status, text);
    return res.status(500).json({ error: 'Could not save your response. Please try again.' });
  }

  return res.status(200).json({ ok: true });
}
