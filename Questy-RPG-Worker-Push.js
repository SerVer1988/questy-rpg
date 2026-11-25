
const ALLOWED_ORIGINS = [
  "https://server1988.github.io",
  "https://dash.cloudflare.com"
];

const SESSION_DAYS = 30;
const PASSWORD_ITERATIONS = 100000;
const MAX_BODY_BYTES = 200000;

function getCorsHeaders(origin) {
  const allowedOrigin = ALLOWED_ORIGINS.includes(origin)
    ? origin
    : "https://server1988.github.io";

  return {
    "Access-Control-Allow-Origin": allowedOrigin,
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Max-Age": "86400",
    "Vary": "Origin",
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store"
  };
}

function json(data, status = 200, origin = "") {
  return new Response(JSON.stringify(data), {
    status,
    headers: getCorsHeaders(origin)
  });
}

function base64(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function base64url(bytes) {
  return base64(bytes)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function fromBase64(value) {
  const binary = atob(value);
  return Uint8Array.from(binary, c => c.charCodeAt(0));
}

async function sha256(value) {
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return base64url(new Uint8Array(digest));
}

async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt,
      iterations: PASSWORD_ITERATIONS,
      hash: "SHA-256"
    },
    key,
    256
  );

  return [
    "pbkdf2",
    PASSWORD_ITERATIONS,
    base64(salt),
    base64(new Uint8Array(bits))
  ].join("$");
}

async function verifyPassword(password, stored) {
  try {
    const [algorithm, iterationsText, saltText, hashText] =
      stored.split("$");

    if (algorithm !== "pbkdf2") return false;

    const iterations = Number(iterationsText);
    if (!Number.isInteger(iterations) || iterations < 10000) {
      return false;
    }

    const salt = fromBase64(saltText);
    const expected = fromBase64(hashText);

    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(password),
      "PBKDF2",
      false,
      ["deriveBits"]
    );

    const bits = await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        salt,
        iterations,
        hash: "SHA-256"
      },
      key,
      256
    );

    const actual = new Uint8Array(bits);

    if (actual.length !== expected.length) return false;

    let difference = 0;
    for (let i = 0; i < actual.length; i++) {
      difference |= actual[i] ^ expected[i];
    }

    return difference === 0;
  } catch {
    return false;
  }
}

async function readBody(request, maxBytes = MAX_BODY_BYTES) {
  const text = await request.text();
  const size = new TextEncoder().encode(text).length;

  if (size > maxBytes) {
    throw new Error("REQUEST_TOO_LARGE");
  }

  try {
    return JSON.parse(text);
  } catch {
    throw new Error("INVALID_JSON");
  }
}

function getBearerToken(request) {
  const header = request.headers.get("Authorization") || "";
  const match = header.match(/^Bearer\s+(.+)$/i);
  return match ? match[1].trim() : null;
}

async function createSession(env, user, origin) {
  const tokenBytes = crypto.getRandomValues(new Uint8Array(32));
  const token = base64url(tokenBytes);
  const tokenHash = await sha256(token);

  const now = Math.floor(Date.now() / 1000);
  const expiresAt = now + SESSION_DAYS * 86400;

  await env.QUESTY_DB.prepare(`
    INSERT INTO sessions
      (id, user_id, token_hash, expires_at, created_at)
    VALUES (?, ?, ?, ?, ?)
  `).bind(
    crypto.randomUUID(),
    user.id,
    tokenHash,
    expiresAt,
    now
  ).run();

  return json({
    ok: true,
    token,
    expiresAt,
    user: {
      id: user.id,
      email: user.email
    }
  }, 200, origin);
}

async function authenticate(request, env) {
  const token = getBearerToken(request);
  if (!token) return null;

  const tokenHash = await sha256(token);
  const now = Math.floor(Date.now() / 1000);

  const result = await env.QUESTY_DB.prepare(`
    SELECT
      users.id,
      users.email,
      sessions.id AS session_id
    FROM sessions
    JOIN users ON users.id = sessions.user_id
    WHERE sessions.token_hash = ?
      AND sessions.expires_at > ?
    LIMIT 1
  `).bind(tokenHash, now).first();

  return result || null;
}

async function register(request, env, origin) {
  if (!env.QUESTY_DB) {
    return json({ error: "Database is not configured" }, 500, origin);
  }

  const body = await readBody(request);
  const email = String(body.email || "").trim().toLowerCase();
  const password = String(body.password || "");

  if (
    email.length < 5 ||
    email.length > 254 ||
    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
  ) {
    return json({ error: "Enter a valid email address" }, 400, origin);
  }

  if (password.length < 10 || password.length > 128) {
    return json({
      error: "Password must contain 10 to 128 characters"
    }, 400, origin);
  }

  const now = Math.floor(Date.now() / 1000);
  const user = {
    id: crypto.randomUUID(),
    email
  };

  const passwordHash = await hashPassword(password);

  try {
    await env.QUESTY_DB.prepare(`
      INSERT INTO users
        (id, email, password_hash, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?)
    `).bind(
      user.id,
      user.email,
      passwordHash,
      now,
      now
    ).run();
  } catch (error) {
    if (String(error.message || error).toLowerCase().includes("unique")) {
      return json({
        error: "An account with this email already exists"
      }, 409, origin);
    }

    throw error;
  }

  return await createSession(env, user, origin);
}

async function login(request, env, origin) {
  if (!env.QUESTY_DB) {
    return json({ error: "Database is not configured" }, 500, origin);
  }

  const body = await readBody(request);
  const email = String(body.email || "").trim().toLowerCase();
  const password = String(body.password || "");

  if (!email || !password || password.length > 128) {
    return json({ error: "Invalid email or password" }, 400, origin);
  }

  const now = Math.floor(Date.now() / 1000);

  const attempts = await env.QUESTY_DB.prepare(`
    SELECT COUNT(*) AS total
    FROM login_attempts
    WHERE email = ?
      AND attempted_at >= ?
      AND successful = 0
  `).bind(email, now - 900).first();

  if (Number(attempts?.total || 0) >= 10) {
    return json({
      error: "Too many login attempts. Try again in 15 minutes."
    }, 429, origin);
  }

  const user = await env.QUESTY_DB.prepare(`
    SELECT id, email, password_hash
    FROM users
    WHERE email = ?
    LIMIT 1
  `).bind(email).first();

  const valid = user
    ? await verifyPassword(password, user.password_hash)
    : false;

  await env.QUESTY_DB.prepare(`
    INSERT INTO login_attempts
      (email, attempted_at, successful)
    VALUES (?, ?, ?)
  `).bind(email, now, valid ? 1 : 0).run();

  if (!valid) {
    return json({
      error: "Invalid email or password"
    }, 401, origin);
  }

  return await createSession(env, user, origin);
}

async function logout(request, env, origin) {
  const token = getBearerToken(request);

  if (token && env.QUESTY_DB) {
    const tokenHash = await sha256(token);

    await env.QUESTY_DB.prepare(`
      DELETE FROM sessions
      WHERE token_hash = ?
    `).bind(tokenHash).run();
  }

  return json({ ok: true }, 200, origin);
}

async function currentUser(request, env, origin) {
  const user = await authenticate(request, env);

  if (!user) {
    return json({ error: "Unauthorized" }, 401, origin);
  }

  return json({
    ok: true,
    user: {
      id: user.id,
      email: user.email
    }
  }, 200, origin);
}

async function saveGame(request, env, origin) {
  const user = await authenticate(request, env);

  if (!user) {
    return json({ error: "Unauthorized" }, 401, origin);
  }

  const body = await readBody(request);

  const saveData = body.saveData ?? body.save_data;

  if (
    !saveData ||
    typeof saveData !== "object" ||
    Array.isArray(saveData)
  ) {
    return json({ error: "saveData must be an object" }, 400, origin);
  }

  const serialized = JSON.stringify(saveData);

  if (new TextEncoder().encode(serialized).length > MAX_BODY_BYTES) {
    return json({ error: "Save data is too large" }, 413, origin);
  }

  const now = Math.floor(Date.now() / 1000);
  const schemaVersion = Number.isInteger(body.schemaVersion)
    ? body.schemaVersion
    : 1;

  await env.QUESTY_DB.prepare(`
    INSERT INTO player_saves
      (user_id, save_data, schema_version, updated_at)
    VALUES (?, ?, ?, ?)
    ON CONFLICT(user_id) DO UPDATE SET
      save_data = excluded.save_data,
      schema_version = excluded.schema_version,
      updated_at = excluded.updated_at
  `).bind(
    user.id,
    serialized,
    schemaVersion,
    now
  ).run();

  return json({
    ok: true,
    updatedAt: now
  }, 200, origin);
}

async function loadGame(request, env, origin) {
  const user = await authenticate(request, env);

  if (!user) {
    return json({ error: "Unauthorized" }, 401, origin);
  }

  const row = await env.QUESTY_DB.prepare(`
    SELECT save_data, schema_version, updated_at
    FROM player_saves
    WHERE user_id = ?
    LIMIT 1
  `).bind(user.id).first();

  if (!row) {
    return json({
      ok: true,
      saveData: null,
      schemaVersion: null,
      updatedAt: null
    }, 200, origin);
  }

  let saveData;

  try {
    saveData = JSON.parse(row.save_data);
  } catch {
    return json({ error: "Stored save data is invalid" }, 500, origin);
  }

  return json({
    ok: true,
    saveData,
    schemaVersion: row.schema_version,
    updatedAt: row.updated_at
  }, 200, origin);
}

async function chat(request, env, origin) {
  if (!env.YANDEX_API_KEY || !env.YANDEX_FOLDER_ID) {
    return json({
      error: "Server configuration is incomplete"
    }, 500, origin);
  }

  const body = await readBody(request, 32000);

  if (!Array.isArray(body.messages) || !body.messages.length) {
    return json({
      error: "messages array is required"
    }, 400, origin);
  }

  const messages = body.messages.slice(-30).map(message => ({
    role: ["system", "user", "assistant"].includes(message.role)
      ? message.role
      : "user",
    content: String(message.content || "").slice(0, 12000)
  }));

  const response = await fetch(
    "https://ai.api.cloud.yandex.net/v1/chat/completions",
    {
      method: "POST",
      headers: {
        "Authorization": `Api-Key ${env.YANDEX_API_KEY}`,
        "OpenAI-Project": env.YANDEX_FOLDER_ID,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        model: `gpt://${env.YANDEX_FOLDER_ID}/aliceai-llm-flash`,
        messages,
        temperature: 0.7,
        max_tokens: 1500
      })
    }
  );

  const result = await response.json();

  if (!response.ok) {
    console.error("Yandex API error:", response.status, result);

    return json({
      error: "AI provider request failed",
      status: response.status
    }, 502, origin);
  }

  return json(result, 200, origin);
}


function bytesToB64Url(bytes) {
  return base64url(bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes));
}
function concatBytes(...parts) {
  const size = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(size); let offset = 0;
  for (const p of parts) { out.set(p, offset); offset += p.length; }
  return out;
}
async function hmacSha256(keyBytes, data) {
  const key = await crypto.subtle.importKey('raw', keyBytes, {name:'HMAC',hash:'SHA-256'}, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, data));
}
async function hkdfExpand(prk, info, length) {
  let previous = new Uint8Array(0), output = new Uint8Array(0), counter = 1;
  while (output.length < length) {
    previous = await hmacSha256(prk, concatBytes(previous, info, new Uint8Array([counter++])));
    output = concatBytes(output, previous);
  }
  return output.slice(0, length);
}
async function hkdfExtract(salt, ikm) { return hmacSha256(salt, ikm); }
function b64urlDecode(value) {
  const s = String(value).replace(/-/g,'+').replace(/_/g,'/');
  return Uint8Array.from(atob(s + '='.repeat((4-s.length%4)%4)), c=>c.charCodeAt(0));
}
async function createVapidJwt(endpoint, env) {
  if (!env.VAPID_PUBLIC_KEY || !env.VAPID_PRIVATE_KEY) throw new Error('VAPID_NOT_CONFIGURED');
  const publicBytes = b64urlDecode(env.VAPID_PUBLIC_KEY);
  const privateBytes = b64urlDecode(env.VAPID_PRIVATE_KEY);
  if (publicBytes.length !== 65 || privateBytes.length !== 32) throw new Error('INVALID_VAPID_KEYS');
  const jwk = {
    kty:'EC', crv:'P-256',
    x:bytesToB64Url(publicBytes.slice(1,33)),
    y:bytesToB64Url(publicBytes.slice(33,65)),
    d:bytesToB64Url(privateBytes), ext:true
  };
  const key = await crypto.subtle.importKey('jwk', jwk, {name:'ECDSA',namedCurve:'P-256'}, false, ['sign']);
  const header = bytesToB64Url(new TextEncoder().encode(JSON.stringify({typ:'JWT',alg:'ES256'})));
  const aud = new URL(endpoint).origin;
  const payload = bytesToB64Url(new TextEncoder().encode(JSON.stringify({aud,exp:Math.floor(Date.now()/1000)+12*60*60,sub:env.VAPID_SUBJECT||'mailto:questy@example.com'})));
  const data = new TextEncoder().encode(header+'.'+payload);
  const signature = new Uint8Array(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},key,data));
  return header+'.'+payload+'.'+bytesToB64Url(signature);
}
async function encryptPushPayload(subscription, payload) {
  const clientPublic = b64urlDecode(subscription.p256dh);
  const authSecret = b64urlDecode(subscription.auth);
  if (clientPublic.length !== 65 || authSecret.length !== 16) throw new Error('INVALID_PUSH_SUBSCRIPTION');
  const clientKey = await crypto.subtle.importKey('raw',clientPublic,{name:'ECDH',namedCurve:'P-256'},false,[]);
  const serverPair = await crypto.subtle.generateKey({name:'ECDH',namedCurve:'P-256'},true,['deriveBits']);
  const serverPublic = new Uint8Array(await crypto.subtle.exportKey('raw',serverPair.publicKey));
  const shared = new Uint8Array(await crypto.subtle.deriveBits({name:'ECDH',public:clientKey},serverPair.privateKey,256));
  const authPrk = await hkdfExtract(authSecret,shared);
  const keyInfo = concatBytes(new TextEncoder().encode('WebPush: info\0'),clientPublic,serverPublic);
  const ikm = await hkdfExpand(authPrk,keyInfo,32);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const prk = await hkdfExtract(salt,ikm);
  const cek = await hkdfExpand(prk,new TextEncoder().encode('Content-Encoding: aes128gcm\0'),16);
  const nonce = await hkdfExpand(prk,new TextEncoder().encode('Content-Encoding: nonce\0'),12);
  const plaintext = concatBytes(new TextEncoder().encode(JSON.stringify(payload)),new Uint8Array([2]));
  const aesKey = await crypto.subtle.importKey('raw',cek,{name:'AES-GCM'},false,['encrypt']);
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv:nonce,tagLength:128},aesKey,plaintext));
  const rs = new Uint8Array([0,0,16,0]); // 4096-byte record size
  return concatBytes(salt,rs,new Uint8Array([serverPublic.length]),serverPublic,ciphertext);
}
async function sendWebPush(row, payload, env) {
  const jwt = await createVapidJwt(row.endpoint,env);
  const body = await encryptPushPayload(row,payload);
  const response = await fetch(row.endpoint,{method:'POST',headers:{
    'Authorization':`vapid t=${jwt}, k=${env.VAPID_PUBLIC_KEY}`,
    'Content-Encoding':'aes128gcm','Content-Type':'application/octet-stream',
    'TTL':'86400','Urgency':'normal'
  },body});
  if (response.status===404 || response.status===410) {
    await env.QUESTY_DB.prepare('DELETE FROM push_subscriptions WHERE endpoint=?').bind(row.endpoint).run();
    return false;
  }
  if (!response.ok) throw new Error('PUSH_HTTP_'+response.status);
  return true;
}
async function pushPublicKey(request,env,origin) {
  if(!env.VAPID_PUBLIC_KEY)return json({error:'Push is not configured'},503,origin);
  return json({ok:true,publicKey:env.VAPID_PUBLIC_KEY},200,origin);
}
async function pushSubscribe(request,env,origin) {
  const user=await authenticate(request,env);
  if(!user)return json({error:'Unauthorized'},401,origin);
  const body=await readBody(request,16000), sub=body.subscription||{};
  const endpoint=String(sub.endpoint||'');
  const p256dh=String(sub.keys?.p256dh||''), auth=String(sub.keys?.auth||'');
  if(!endpoint.startsWith('https://')||p256dh.length<40||auth.length<16)return json({error:'Invalid push subscription'},400,origin);
  const timezone=String(body.timezone||'UTC').slice(0,80);
  try { new Intl.DateTimeFormat('en-US',{timeZone:timezone}); } catch { return json({error:'Invalid timezone'},400,origin); }
  const now=Math.floor(Date.now()/1000);
  await env.QUESTY_DB.prepare(`INSERT INTO push_subscriptions(user_id,endpoint,p256dh,auth,timezone,created_at,updated_at)
    VALUES(?,?,?,?,?,?,?) ON CONFLICT(endpoint) DO UPDATE SET user_id=excluded.user_id,p256dh=excluded.p256dh,auth=excluded.auth,timezone=excluded.timezone,updated_at=excluded.updated_at`)
    .bind(user.id,endpoint,p256dh,auth,timezone,now,now).run();
  return json({ok:true},200,origin);
}
async function pushUnsubscribe(request,env,origin) {
  const user=await authenticate(request,env);
  if(!user)return json({error:'Unauthorized'},401,origin);
  const body=await readBody(request,4000), endpoint=String(body.endpoint||'');
  await env.QUESTY_DB.prepare('DELETE FROM push_subscriptions WHERE user_id=? AND endpoint=?').bind(user.id,endpoint).run();
  return json({ok:true},200,origin);
}
async function pushTest(request,env,origin) {
  const user=await authenticate(request,env);
  if(!user)return json({error:'Unauthorized'},401,origin);
  const row=await env.QUESTY_DB.prepare('SELECT * FROM push_subscriptions WHERE user_id=? LIMIT 1').bind(user.id).first();
  if(!row)return json({error:'No push subscription'},404,origin);
  await sendWebPush(row,{title:'Фокси на связи! 🦊',body:'Уведомления Questy работают. До скорой встречи!',url:'https://server1988.github.io/questy-rpg/'},env);
  return json({ok:true},200,origin);
}
function localParts(date, timezone) {
  const p=new Intl.DateTimeFormat('en-CA',{timeZone:timezone,year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',hourCycle:'h23'}).formatToParts(date);
  const o={}; for(const x of p)if(x.type!=='literal')o[x.type]=x.value;
  return {date:`${o.year}-${o.month}-${o.day}`,hour:Number(o.hour)};
}
function tomorrowIso(date) { const d=new Date(date+'T12:00:00Z');d.setUTCDate(d.getUTCDate()+1);return d.toISOString().slice(0,10); }
async function runPushSchedule(env) {
  if(!env.QUESTY_DB||!env.VAPID_PUBLIC_KEY||!env.VAPID_PRIVATE_KEY)return;
  const rows=await env.QUESTY_DB.prepare(`SELECT ps.*, sv.save_data FROM push_subscriptions ps
    JOIN player_saves sv ON sv.user_id=ps.user_id`).all();
  for(const row of rows.results||[]) {
    try {
      const now=localParts(new Date(),row.timezone||'UTC');
      if(now.hour!==9)continue;
      const save=JSON.parse(row.save_data||'{}');
      const notices=[];
      for(const list of (save.todoLists||[])) {
        if(list.date!==now.date)continue;
        if(list.generatedByDate&&list.generatedByDate[now.date])continue;
        const item=(list.items||[]).find(x=>!x.done);
        if(item)notices.push({key:`todo:${list.id}:${now.date}`,title:'Фокси приготовил квест 🦊',body:`Сегодня из списка «${String(list.title||'Мои дела').slice(0,70)}»: ${String(item.title||'Один маленький шаг').slice(0,110)}`,url:'https://server1988.github.io/questy-rpg/'});
      }
      const tomorrow=tomorrowIso(now.date);
      for(const ev of (save.events||[])) {
        const cat=(save.eventCategories||[]).find(c=>c.id===ev.category);
        const birthday=/birthday|дни рожд|день рожд/i.test(String(ev.category||'')+' '+String(cat?.name||''));
        if(!birthday||!ev.date)continue;
        const occurs=ev.recurrence==='annual'||ev.legacyType==='annual'?ev.date.slice(5)===tomorrow.slice(5):ev.date===tomorrow;
        if(!occurs)continue;
        const key=`birthday:${ev.id}:${tomorrow.slice(0,4)}`;
        if((save.birthdayQuestLog||[]).includes(`${ev.id}:${tomorrow.slice(0,4)}`))continue;
        notices.push({key,title:'Завтра важный день 🎂',body:`Фокси напоминает: подготовь поздравление — ${String(ev.title||'день рождения').slice(0,100)}`,url:'https://server1988.github.io/questy-rpg/'});
      }
      for(const n of notices) {
        const deviceKey=n.key+':'+(await sha256(row.endpoint)).slice(0,24);
        const already=await env.QUESTY_DB.prepare('SELECT 1 AS ok FROM push_deliveries WHERE user_id=? AND delivery_key=?').bind(row.user_id,deviceKey).first();
        if(already)continue;
        await sendWebPush(row,{title:n.title,body:n.body,url:n.url},env);
        await env.QUESTY_DB.prepare('INSERT OR IGNORE INTO push_deliveries(user_id,delivery_key,delivered_at) VALUES(?,?,?)').bind(row.user_id,deviceKey,Math.floor(Date.now()/1000)).run();
      }
    } catch(error) { console.error('Scheduled push failed for user',row.user_id,error); }
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const origin = request.headers.get("Origin") || "";
    const path = url.pathname;

    if (origin && !ALLOWED_ORIGINS.includes(origin)) {
      return json({ error: "Origin not allowed" }, 403, origin);
    }

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: getCorsHeaders(origin)
      });
    }

    if (path === "/" && request.method === "GET") {
      return json({
        service: "Questy RPG AI",
        status: "online",
        model: "Alice AI LLM Flash",
        database: env.QUESTY_DB ? "connected" : "not configured"
      }, 200, origin);
    }

    try {
      if (path === "/chat" && request.method === "POST") {
        return await chat(request, env, origin);
      }

      if (path === "/auth/register" && request.method === "POST") {
        return await register(request, env, origin);
      }

      if (path === "/auth/login" && request.method === "POST") {
        return await login(request, env, origin);
      }

      if (path === "/auth/logout" && request.method === "POST") {
        return await logout(request, env, origin);
      }

      if (path === "/auth/me" && request.method === "GET") {
        return await currentUser(request, env, origin);
      }

      if (path === "/save" && request.method === "POST") {
        return await saveGame(request, env, origin);
      }

      if (path === "/load" && request.method === "GET") {
        return await loadGame(request, env, origin);
      }

      if (path === "/push/public-key" && request.method === "GET") return await pushPublicKey(request,env,origin);
      if (path === "/push/subscribe" && request.method === "POST") return await pushSubscribe(request,env,origin);
      if (path === "/push/unsubscribe" && request.method === "POST") return await pushUnsubscribe(request,env,origin);
      if (path === "/push/test" && request.method === "POST") return await pushTest(request,env,origin);

      const knownPaths = [
        "/", "/chat",
        "/auth/register", "/auth/login",
        "/auth/logout", "/auth/me",
        "/save", "/load", "/push/public-key", "/push/subscribe", "/push/unsubscribe", "/push/test"
      ];

      if (knownPaths.includes(path)) {
        return json({ error: "Method not allowed" }, 405, origin);
      }

      return json({ error: "Not found" }, 404, origin);

    } catch (error) {
      console.error("Worker error:", error);

      if (error.message === "REQUEST_TOO_LARGE") {
        return json({ error: "Request too large" }, 413, origin);
      }

      if (error.message === "INVALID_JSON") {
        return json({ error: "Invalid JSON" }, 400, origin);
      }

      // TEMPORARY REGISTRATION DIAGNOSTICS:
      // Return only the error message (not stack traces or secrets) so the
      // registration failure can be identified from the app response.
      if (path === "/auth/register") {
        return json({
          error: "Registration failed: " + String(error?.message || error)
        }, 500, origin);
      }

      return json({
        error: "Internal server error"
      }, 500, origin);
    }
  }
  ,
  async scheduled(controller, env, ctx) { ctx.waitUntil(runPushSchedule(env)); }
};
