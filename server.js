const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers":
    "Content-Type, Authorization, X-Hub-Signature-256"
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      ...corsHeaders,
      "Content-Type": "application/json"
    }
  });
}

function basicAuth(request, env) {
  const header = request.headers.get("Authorization") || "";

  if (!header.startsWith("Basic ")) return false;

  try {
    const decoded = atob(header.slice(6));
    const index = decoded.indexOf(":");

    if (index < 0) return false;

    const user = decoded.slice(0, index);
    const pass = decoded.slice(index + 1);

    return (
      user === env.INBOX_USER &&
      pass === env.INBOX_PASSWORD &&
      !!env.INBOX_USER &&
      !!env.INBOX_PASSWORD
    );
  } catch {
    return false;
  }
}

async function verifySignature(request, rawBody, secret) {
  if (!secret) return false;

  const signature =
    request.headers.get("X-Hub-Signature-256") || "";

  if (!signature.startsWith("sha256=")) return false;

  try {
    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );

    const digest = await crypto.subtle.sign(
      "HMAC",
      key,
      new TextEncoder().encode(rawBody)
    );

    const expected =
      "sha256=" +
      Array.from(new Uint8Array(digest))
        .map(b => b.toString(16).padStart(2, "0"))
        .join("");

    if (signature.length !== expected.length) return false;

    let difference = 0;

    for (let i = 0; i < signature.length; i++) {
      difference |= signature.charCodeAt(i) ^ expected.charCodeAt(i);
    }

    return difference === 0;
  } catch {
    return false;
  }
}

async function saveMessage(
  env,
  platform,
  customerId,
  text,
  id,
  name = null,
  time = null
) {
  const conversationId = `${platform}:${customerId}`;
  const createdAt = time || new Date().toISOString();
  const messageId = String(id || crypto.randomUUID());

  await env.DB.prepare(`
    INSERT INTO conversations
    (id, platform, customer_id, customer_name, last_message, last_at, unread)
    VALUES (?, ?, ?, ?, ?, ?, 1)
    ON CONFLICT(id) DO UPDATE SET
      customer_name = COALESCE(excluded.customer_name, conversations.customer_name),
      last_message = excluded.last_message,
      last_at = excluded.last_at,
      unread = conversations.unread + 1
  `).bind(
    conversationId,
    platform,
    String(customerId),
    name,
    text,
    createdAt
  ).run();

  await env.DB.prepare(`
    INSERT OR IGNORE INTO messages
    (id, conversation_id, platform, direction, body, created_at, sender_name, status)
    VALUES (?, ?, ?, 'in', ?, ?, ?, 'received')
  `).bind(
    messageId,
    conversationId,
    platform,
    text,
    createdAt,
    name
  ).run();
}

async function handleWebhook(request, env) {
  const url = new URL(request.url);

  if (request.method === "GET") {
    const mode = url.searchParams.get("hub.mode");
    const token = url.searchParams.get("hub.verify_token");
    const challenge = url.searchParams.get("hub.challenge");

    if (
      mode === "subscribe" &&
      token &&
      token === env.META_VERIFY_TOKEN
    ) {
      return new Response(challenge || "", {
        status: 200
      });
    }

    return new Response("Forbidden", { status: 403 });
  }

  if (request.method !== "POST") {
    return new Response("Method not allowed", { status: 405 });
  }

  const raw = await request.text();

  const valid = await verifySignature(
    request,
    raw,
    env.META_APP_SECRET
  );

  if (!valid) {
    return new Response("Invalid signature", { status: 401 });
  }

  let body;

  try {
    body = JSON.parse(raw);
  } catch {
    return new Response("Invalid JSON", { status: 400 });
  }

  try {
    if (body.object === "whatsapp_business_account") {
      for (const entry of body.entry || []) {
        for (const change of entry.changes || []) {
          if (change.field !== "messages") continue;

          const value = change.value || {};
          const contacts = value.contacts || [];

          for (const message of value.messages || []) {
            const contact = contacts.find(
              c => c.wa_id === message.from
            );

            const time = message.timestamp
              ? new Date(
                  Number(message.timestamp) * 1000
                ).toISOString()
              : null;

            await saveMessage(
              env,
              "whatsapp",
              message.from,
              message.text?.body || `[${message.type || "media"}]`,
              message.id,
              contact?.profile?.name || null,
              time
            );
          }
        }
      }
    } else if (
      body.object === "page" ||
      body.object === "instagram"
    ) {
      const platform =
        body.object === "instagram" ? "instagram" : "facebook";

      for (const entry of body.entry || []) {
        for (const event of entry.messaging || []) {
          if (
            !event.message ||
            event.message.is_echo ||
            !event.sender?.id
          ) {
            continue;
          }

          await saveMessage(
            env,
            platform,
            event.sender.id,
            event.message.text || "[محتوى غير نصي]",
            event.message.mid,
            null,
            event.timestamp
              ? new Date(Number(event.timestamp)).toISOString()
              : null
          );
        }
      }
    }

    return new Response("EVENT_RECEIVED", { status: 200 });
  } catch (error) {
    console.error("Webhook error:", error);

    return new Response("Webhook processing failed", {
      status: 500
    });
  }
}

async function sendMessage(request, env) {
  let data;

  try {
    data = await request.json();
  } catch {
    return json({ error: "Invalid JSON" }, 400);
  }

  const { conversationId, text, operator } = data;

  if (!conversationId || !text?.trim()) {
    return json({
      error: "conversationId and text are required"
    }, 400);
  }

  const conversation = await env.DB.prepare(
    "SELECT * FROM conversations WHERE id = ?"
  ).bind(conversationId).first();

  if (!conversation) {
    return json({ error: "Conversation not found" }, 404);
  }

  const version = env.GRAPH_API_VERSION;

  if (!version) {
    return json({ error: "Graph API version missing" }, 500);
  }

  let token;
  let url;
  let payload;

  if (conversation.platform === "whatsapp") {
    token = env.WHATSAPP_ACCESS_TOKEN;

    if (!env.WHATSAPP_PHONE_NUMBER_ID) {
      return json({ error: "WhatsApp phone ID missing" }, 500);
    }

    url = `https://graph.facebook.com/${version}/${env.WHATSAPP_PHONE_NUMBER_ID}/messages`;

    payload = {
      messaging_product: "whatsapp",
      recipient_type: "individual",
      to: conversation.customer_id,
      type: "text",
      text: {
        preview_url: false,
        body: text.trim()
      }
    };
  } else if (conversation.platform === "facebook") {
    token = env.FACEBOOK_PAGE_ACCESS_TOKEN;

    if (!env.FACEBOOK_PAGE_ID) {
      return json({ error: "Facebook page ID missing" }, 500);
    }

    url = `https://graph.facebook.com/${version}/${env.FACEBOOK_PAGE_ID}/messages`;

    payload = {
      recipient: { id: conversation.customer_id },
      messaging_type: "RESPONSE",
      message: { text: text.trim() }
    };
  } else if (conversation.platform === "instagram") {
    token = env.INSTAGRAM_PAGE_ACCESS_TOKEN;

    if (!env.INSTAGRAM_ACCOUNT_ID) {
      return json({ error: "Instagram account ID missing" }, 500);
    }

    url = `https://graph.facebook.com/${version}/${env.INSTAGRAM_ACCOUNT_ID}/messages`;

    payload = {
      recipient: { id: conversation.customer_id },
      message: { text: text.trim() }
    };
  } else {
    return json({ error: "Unsupported platform" }, 400);
  }

  if (!token) {
    return json({ error: "Platform access token missing" }, 500);
  }

  const response = await fetch(url, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify(payload)
  });

  let result;

  try {
    result = await response.json();
  } catch {
    result = {};
  }

  if (!response.ok) {
    return json({
      error: "Meta send failed",
      details: result
    }, response.status);
  }

  const id =
    result.message_id ||
    result.messages?.[0]?.id ||
    crypto.randomUUID();

  const createdAt = new Date().toISOString();

  await env.DB.prepare(`
    INSERT OR IGNORE INTO messages
    (id, conversation_id, platform, direction, body, created_at, sender_name, status)
    VALUES (?, ?, ?, 'out', ?, ?, ?, 'sent')
  `).bind(
    String(id),
    conversationId,
    conversation.platform,
    text.trim(),
    createdAt,
    operator || "موظف"
  ).run();

  await env.DB.prepare(`
    UPDATE conversations
    SET last_message = ?, last_at = ?
    WHERE id = ?
  `).bind(
    text.trim(),
    createdAt,
    conversationId
  ).run();

  return json({ ok: true, id });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: corsHeaders
      });
    }

    try {
      if (path === "/webhooks/meta") {
        return await handleWebhook(request, env);
      }

      if (path.startsWith("/api/")) {
        if (!basicAuth(request, env)) {
          return new Response("Authentication required", {
            status: 401,
            headers: {
              ...corsHeaders,
              "WWW-Authenticate": 'Basic realm="Crispy Town Inbox"'
            }
          });
        }

        if (!env.DB) {
          return json({ error: "D1 database binding DB is missing" }, 500);
        }

        if (path === "/api/status" && request.method === "GET") {
          return json({
            ok: true,
            database: true,
            configured: {
              facebook: !!(
                env.FACEBOOK_PAGE_ID &&
                env.FACEBOOK_PAGE_ACCESS_TOKEN
              ),
              instagram: !!(
                env.INSTAGRAM_ACCOUNT_ID &&
                env.INSTAGRAM_PAGE_ACCESS_TOKEN
              ),
              whatsapp: !!(
                env.WHATSAPP_PHONE_NUMBER_ID &&
                env.WHATSAPP_ACCESS_TOKEN
              )
            },
            webhook: "/webhooks/meta"
          });
        }

        if (
          path === "/api/conversations" &&
          request.method === "GET"
        ) {
          const result = await env.DB.prepare(
            "SELECT * FROM conversations ORDER BY last_at DESC LIMIT 300"
          ).all();

          return json(result.results || []);
        }

        if (
          path.startsWith("/api/conversations/") &&
          path.endsWith("/messages") &&
          request.method === "GET"
        ) {
          const id = decodeURIComponent(
            path.slice(
              "/api/conversations/".length,
              -"/messages".length
            )
          );

          const result = await env.DB.prepare(
            "SELECT * FROM messages WHERE conversation_id = ? ORDER BY created_at ASC LIMIT 500"
          ).bind(id).all();

          await env.DB.prepare(
            "UPDATE conversations SET unread = 0 WHERE id = ?"
          ).bind(id).run();

          return json(result.results || []);
        }

        if (path === "/api/send" && request.method === "POST") {
          return await sendMessage(request, env);
        }

        return json({ error: "API route not found" }, 404);
      }

      if (path === "/") {
        return new Response("Crispy Town Worker is running", {
          status: 200,
          headers: corsHeaders
        });
      }

      return json({ error: "Not found" }, 404);
    } catch (error) {
      console.error("Worker error:", error);

      return json({
        error: "Internal server error"
      }, 500);
    }
  }
};
