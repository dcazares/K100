// Handles: POST /api/log  -> forwards to Apps Script (10 columns + meta_json)
// Also serves static files (index.html) for everything else.

const clamp = (s, n) => (s || '').toString().slice(0, n).replace(/[\u0000-\u001F]+/g, '');
const round2 = (v) => (v === undefined || v === null || v === '') ? '' : String(Math.round(parseFloat(v) * 100) / 100);

function uuidv4() {
  const b = new Uint8Array(16); crypto.getRandomValues(b);
  b[6] = (b[6] & 0x0f) | 0x40; b[8] = (b[8] & 0x3f) | 0x80;
  const h = [...b].map(x => x.toString(16).padStart(2,'0')).join('');
  return `${h.slice(0,8)}-${h.slice(8,12)}-${h.slice(12,16)}-${h.slice(16,20)}-${h.slice(20)}`;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // API route
    if (url.pathname === '/api/log') {
      if (request.method === 'OPTIONS') {
        return new Response(null, {
          status: 204,
          headers: {
            'Access-Control-Allow-Origin': url.origin,
            'Access-Control-Allow-Methods': 'POST, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type',
            'Access-Control-Max-Age': '600'
          }
        });
      }

      if (request.method !== 'POST') {
        return new Response(JSON.stringify({ ok:false, error:'POST only' }), { status:405, headers:{'Content-Type':'application/json'} });
      }

      const incoming = await request.json().catch(() => ({}));
      // Honeypot
      if ((incoming.honey || '').trim() !== '') {
        return new Response(JSON.stringify({ ok:true, skipped:'honeypot' }), { status:200, headers:{'Content-Type':'application/json'} });
      }

      // Normalize & enrich
      const nowIso = new Date().toISOString();
      const cf = request.cf || {};
      const ipHeader = request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For') || '';
      const ip = ipHeader.split(',')[0].trim();
      const ua = clamp(request.headers.get('User-Agent'), 512);
      const referer = clamp(request.headers.get('Referer'), 512);
      const acceptLang = clamp(request.headers.get('Accept-Language'), 128);

      const tokenId = clamp((incoming.token_id || '').toUpperCase(), 32);
      if (!tokenId) {
        return new Response(JSON.stringify({ ok:false, error:'TOKEN_ID_REQUIRED' }), { status:400, headers:{'Content-Type':'application/json'} });
      }

      // Core columns we keep in the sheet
      const core = {
        event_id: uuidv4(),
        timestamp_iso: nowIso,
        token_id: tokenId,
        story: clamp(incoming.story, 4000),
        city: clamp(cf.city, 120),
        country: clamp(cf.country, 8),
        channel: clamp(incoming.channel || 'card', 64),
        batch: clamp(incoming.batch || '', 64),
        consent_public: String(incoming.consent_public || '').toLowerCase() === 'true'
      };

      // Everything else → meta_json
      const meta = {
        timezone_edge: clamp(cf.timezone, 64),
        timezone_client: clamp(incoming.timezone_client, 64),
        lat: round2(cf.latitude),
        lon: round2(cf.longitude),
        ip: clamp(ip, 64),
        user_agent: ua,
        utm_source: clamp(incoming.utm_source, 120),
        utm_medium: clamp(incoming.utm_medium, 120),
        utm_campaign: clamp(incoming.utm_campaign, 120),
        utm_content: clamp(incoming.utm_content, 120),
        utm_term: clamp(incoming.utm_term, 120),
        qr_id: clamp(incoming.qr_id, 64),
        drop_id: clamp(incoming.drop_id, 64),
        referer, accept_language: acceptLang
      };

      // Forward to Google Apps Script (secret proves authenticity)
      const upstream = await fetch(env.GOOGLE_WEBHOOK_URL, {
        method: 'POST',
        headers: { 'Content-Type':'application/json' },
        body: JSON.stringify({ ...core, meta_json: JSON.stringify(meta), _secret: env.K100_SECRET })
      });

      if (!upstream.ok) {
        const text = await upstream.text();
        return new Response(JSON.stringify({ ok:false, upstream_error:text }), { status:502, headers:{'Content-Type':'application/json'} });
      }

      return new Response(JSON.stringify({ ok:true }), {
        status: 200,
        headers: {
          'Content-Type': 'application/json',
          'Cache-Control': 'no-store',
          'Access-Control-Allow-Origin': url.origin
        }
      });
    }

    // Static site (serves index.html and assets)
    return env.ASSETS.fetch(request);
  }
}
