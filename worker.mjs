const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const USERNAME_PATTERN = /^[a-z0-9._-]{3,24}$/;
const ROLES = ['SUPER ADMIN', 'Admin', 'Tech Support', 'Moderator', 'Staff'];
const SESSION_COOKIE = '__Host-axium_session';
const SESSION_TTL_SECONDS = 60 * 60 * 8;
const PASSWORD_ITERATIONS = 120000;
const encoder = new TextEncoder();
let cachedAccessKeys = null;
let cachedAccessDomain = null;
let cachedAccessKeysExpiresAt = 0;

function json(data, status = 200, headers = {}) {
    return new Response(JSON.stringify(data), {
        status,
        headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...headers }
    });
}

function getAccessDomain(env) {
    return typeof env.ACCESS_TEAM_DOMAIN === 'string'
        ? env.ACCESS_TEAM_DOMAIN.trim().replace(/^https?:\/\//, '').replace(/\/$/, '').toLowerCase()
        : '';
}

function decodeBase64Url(value) {
    const base64 = value.replace(/-/g, '+').replace(/_/g, '/');
    const padded = base64 + '='.repeat((4 - base64.length % 4) % 4);
    return Uint8Array.from(atob(padded), character => character.charCodeAt(0));
}

function decodeJwtJson(value) {
    return JSON.parse(new TextDecoder().decode(decodeBase64Url(value)));
}

function encodeBase64(bytes) {
    return btoa(String.fromCharCode(...new Uint8Array(bytes)));
}

function decodeBase64(value) {
    return Uint8Array.from(atob(value), character => character.charCodeAt(0));
}

function makeSessionCookie(token, maxAge = SESSION_TTL_SECONDS) {
    return `${SESSION_COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}`;
}

function readSessionCookie(request) {
    const cookies = (request.headers.get('Cookie') || '').split(';').map(part => part.trim());
    const cookie = cookies.find(part => part.startsWith(`${SESSION_COOKIE}=`));
    return cookie ? cookie.slice(SESSION_COOKIE.length + 1) : null;
}

async function hashPassword(password, salt = crypto.getRandomValues(new Uint8Array(16))) {
    const key = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']);
    const hash = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: PASSWORD_ITERATIONS }, key, 256);
    return { salt: encodeBase64(salt), passwordHash: encodeBase64(hash) };
}

async function verifyPassword(password, account) {
    if (!account.passwordHash || !account.salt) return false;
    const result = await hashPassword(password, decodeBase64(account.salt));
    const expected = decodeBase64(account.passwordHash);
    const actual = decodeBase64(result.passwordHash);
    return expected.length === actual.length && expected.reduce((difference, byte, index) => difference | (byte ^ actual[index]), 0) === 0;
}

async function getAccessSigningKey(env, keyId) {
    const domain = getAccessDomain(env);
    if (!domain || typeof env.ACCESS_AUD !== 'string' || !env.ACCESS_AUD.trim()) {
        throw Object.assign(new Error('Cloudflare Access is not configured. Set ACCESS_TEAM_DOMAIN and ACCESS_AUD.'), { status: 503 });
    }
    if (!cachedAccessKeys || cachedAccessDomain !== domain || cachedAccessKeysExpiresAt <= Date.now()) {
        const response = await fetch(`https://${domain}/cdn-cgi/access/certs`);
        if (!response.ok) throw Object.assign(new Error('Could not load Cloudflare Access signing keys.'), { status: 503 });
        const certs = await response.json();
        if (!Array.isArray(certs.keys)) throw Object.assign(new Error('Cloudflare Access returned an invalid signing-key set.'), { status: 503 });
        cachedAccessKeys = certs.keys;
        cachedAccessDomain = domain;
        cachedAccessKeysExpiresAt = Date.now() + 5 * 60 * 1000;
    }
    const jwk = cachedAccessKeys.find(key => key.kid === keyId && key.kty === 'RSA' && key.use === 'sig');
    if (!jwk) throw Object.assign(new Error('Cloudflare Access signing key was not found.'), { status: 401 });
    return crypto.subtle.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
}

async function getAccessIdentity(request, env) {
    const token = request.headers.get('Cf-Access-Jwt-Assertion');
    if (!token) return null;
    const parts = token.split('.');
    if (parts.length !== 3) throw Object.assign(new Error('Invalid Cloudflare Access token.'), { status: 401 });

    let header;
    let claims;
    let signature;
    try {
        header = decodeJwtJson(parts[0]);
        claims = decodeJwtJson(parts[1]);
        signature = decodeBase64Url(parts[2]);
    } catch {
        throw Object.assign(new Error('Invalid Cloudflare Access token.'), { status: 401 });
    }
    if (header.alg !== 'RS256' || typeof header.kid !== 'string') {
        throw Object.assign(new Error('Unsupported Cloudflare Access token signature.'), { status: 401 });
    }

    const domain = getAccessDomain(env);
    const key = await getAccessSigningKey(env, header.kid);
    const signedContent = encoder.encode(`${parts[0]}.${parts[1]}`);
    if (!await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, signature, signedContent)) {
        throw Object.assign(new Error('Cloudflare Access token signature is invalid.'), { status: 401 });
    }

    const now = Math.floor(Date.now() / 1000);
    const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
    if (claims.iss !== `https://${domain}` || !audiences.includes(env.ACCESS_AUD.trim()) ||
        !Number.isFinite(claims.exp) || claims.exp <= now ||
        (Number.isFinite(claims.nbf) && claims.nbf > now) ||
        (Number.isFinite(claims.iat) && claims.iat > now + 60)) {
        throw Object.assign(new Error('Cloudflare Access token claims are invalid or expired.'), { status: 401 });
    }

    const email = typeof claims.email === 'string' ? claims.email.trim().toLowerCase() : '';
    if (!EMAIL_PATTERN.test(email) || email.length > 254) {
        throw Object.assign(new Error('Cloudflare Access token does not contain a valid email identity.'), { status: 401 });
    }
    return { email, name: typeof claims.name === 'string' ? claims.name : email, expiresAt: claims.exp };
}

async function readBody(request) {
    const text = await request.text();
    if (text.length > 24000) throw new Error('Request body is too large.');
    return text ? JSON.parse(text) : {};
}

async function getAccount(env, email) {
    if (typeof email !== 'string' || !EMAIL_PATTERN.test(email) || email.length > 254) return null;
    return env.AXIUM_KV.get(`user:${email.trim().toLowerCase()}`, 'json');
}

async function getAccountByUsername(env, username) {
    const normalized = typeof username === 'string' ? username.trim().toLowerCase() : '';
    if (!USERNAME_PATTERN.test(normalized)) return null;
    const accountReference = await env.AXIUM_KV.get(`username:${normalized}`);
    if (!accountReference) return null;
    return accountReference.startsWith('user:')
        ? env.AXIUM_KV.get(accountReference, 'json')
        : getAccount(env, accountReference);
}

async function getAuthMode(env) {
    return await env.AXIUM_KV.get('system:auth_mode') || 'local';
}

async function createSession(env, account, mode, ttl = SESSION_TTL_SECONDS) {
    const token = encodeBase64(crypto.getRandomValues(new Uint8Array(32))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    const tokenHash = encodeBase64(await crypto.subtle.digest('SHA-256', encoder.encode(token)));
    const maxAge = Math.max(1, Math.min(SESSION_TTL_SECONDS, Math.floor(ttl)));
    await env.AXIUM_KV.put(`session:${tokenHash}`, JSON.stringify({ username: account.username, mode, expiresAt: Date.now() + maxAge * 1000 }), { expirationTtl: maxAge });
    return { cookie: makeSessionCookie(token, maxAge), tokenHash };
}

async function getSession(request, env) {
    const token = readSessionCookie(request);
    if (!token) return null;
    const tokenHash = encodeBase64(await crypto.subtle.digest('SHA-256', encoder.encode(token)));
    const session = await env.AXIUM_KV.get(`session:${tokenHash}`, 'json');
    if (!session || session.expiresAt <= Date.now() || session.mode !== await getAuthMode(env)) {
        await env.AXIUM_KV.delete(`session:${tokenHash}`);
        return null;
    }
    const account = await getAccountByUsername(env, session.username);
    if (!account) {
        await env.AXIUM_KV.delete(`session:${tokenHash}`);
        return null;
    }
    return { ...account, tokenHash };
}

function requireRole(account, roles) {
    return roles.includes(account.role);
}

function assertSameOrigin(request) {
    const origin = request.headers.get('Origin');
    if (!origin || origin !== new URL(request.url).origin) {
        throw Object.assign(new Error('Request origin is not allowed.'), { status: 403 });
    }
}

async function listRecords(kv, prefix) {
    const records = [];
    let cursor;
    do {
        const page = await kv.list({ prefix, ...(cursor ? { cursor } : {}) });
        const pageRecords = await Promise.all(page.keys.map(key => kv.get(key.name, 'json')));
        records.push(...pageRecords.filter(Boolean));
        cursor = page.list_complete ? undefined : page.cursor;
    } while (cursor);
    return records;
}

async function listUsers(env) {
    return listRecords(env.AXIUM_KV, 'user:');
}

async function listTickets(env) {
    const tickets = await listRecords(env.AXIUM_KV, 'ticket:');
    return tickets.sort((left, right) => right.createdAt.localeCompare(left.createdAt));
}

async function getTicket(env, id) {
    return env.AXIUM_KV.get(`ticket:${id}`, 'json');
}

async function saveTicket(env, ticket) {
    await env.AXIUM_KV.put(`ticket:${ticket.id}`, JSON.stringify(ticket));
}

async function writeAuditEvent(env, account, action, details = {}) {
    const createdAt = new Date().toISOString();
    const key = `audit:${createdAt}:${crypto.randomUUID()}`;
    try {
        await env.AXIUM_KV.put(key, JSON.stringify({
            id: key.slice('audit:'.length),
            action,
            actor: account.username,
            role: account.role,
            details,
            createdAt
        }));
    } catch (error) {
        console.error('Could not persist the audit event:', error);
    }
}

async function discordApi(env, path, method = 'GET', payload) {
    if (!env.DISCORD_BOT_TOKEN) throw new Error('Discord bot token is not configured.');
    const response = await fetch(`https://discord.com/api/v10${path}`, {
        method,
        headers: { 'authorization': `Bot ${env.DISCORD_BOT_TOKEN}`, ...(payload ? { 'content-type': 'application/json' } : {}) },
        ...(payload ? { body: JSON.stringify(payload) } : {})
    });
    const result = response.status === 204 ? null : await response.json().catch(() => null);
    if (!response.ok) throw new Error(result?.message || `Discord API returned ${response.status}.`);
    return result;
}

async function telegramApi(env, method, payload) {
    if (!env.TELEGRAM_BOT_TOKEN) throw new Error('Telegram bot token is not configured.');
    const response = await fetch(`https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/${method}`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(payload)
    });
    const result = await response.json().catch(() => null);
    if (!response.ok || !result?.ok) throw new Error(result?.description || `Telegram API returned ${response.status}.`);
    return result.result;
}

function ticketSummary(ticket) {
    return `Ticket ${ticket.id}: ${ticket.title}\nStatus: ${ticket.status}\nPriority: ${ticket.priority}\nCategory: ${ticket.category}\nOpened by: ${ticket.author} (${ticket.role})\n\n${ticket.desc}`;
}

async function postTelegramTopicMessage(env, ticket, text) {
    const destination = ticket.messaging?.telegram;
    if (!destination) return;
    try {
        await telegramApi(env, 'sendMessage', {
            chat_id: destination.chatId,
            message_thread_id: destination.threadId,
            text: text.slice(0, 4000)
        });
    } catch (error) {
        console.error(`Could not post ticket ${ticket.id} to Telegram:`, error);
    }
}

async function postDiscordChannelMessage(env, ticket, text) {
    const destination = ticket.messaging?.discord;
    if (!destination) return;
    try {
        await discordApi(env, `/channels/${destination.channelId}/messages`, 'POST', {
            content: text.slice(0, 1900),
            allowed_mentions: { parse: [] }
        });
    } catch (error) {
        console.error(`Could not post ticket ${ticket.id} to Discord:`, error);
    }
}

async function broadcastTicketMessage(env, ticket, text, skipPlatform = '') {
    const deliveries = [];
    if (skipPlatform !== 'telegram') deliveries.push(postTelegramTopicMessage(env, ticket, text));
    if (skipPlatform !== 'discord') deliveries.push(postDiscordChannelMessage(env, ticket, text));
    await Promise.all(deliveries);
}

async function provisionTicketMessaging(env, ticket) {
    ticket.messaging = ticket.messaging || {};
    const errors = [];

    if (env.TELEGRAM_BOT_TOKEN && env.TELEGRAM_FORUM_CHAT_ID) {
        try {
            const topic = await telegramApi(env, 'createForumTopic', {
                chat_id: env.TELEGRAM_FORUM_CHAT_ID,
                name: `${ticket.id} ${ticket.title}`.slice(0, 128)
            });
            ticket.messaging.telegram = { chatId: String(env.TELEGRAM_FORUM_CHAT_ID), threadId: topic.message_thread_id };
            await env.AXIUM_KV.put(`telegram_topic:${topic.message_thread_id}`, ticket.id);
            await postTelegramTopicMessage(env, ticket, ticketSummary(ticket));
        } catch (error) {
            errors.push(`Telegram: ${error.message}`);
        }
    }

    if (env.DISCORD_BOT_TOKEN && env.DISCORD_GUILD_ID && env.DISCORD_SUPPORT_CATEGORY_ID && env.DISCORD_SUPPORT_ROLE_ID) {
        try {
            const channel = await discordApi(env, `/guilds/${env.DISCORD_GUILD_ID}/channels`, 'POST', {
                name: `${ticket.id}-${ticket.title}`.toLowerCase().replace(/[^a-z0-9-]+/g, '-').replace(/^-|-$/g, '').slice(0, 95),
                type: 0,
                parent_id: env.DISCORD_SUPPORT_CATEGORY_ID,
                permission_overwrites: [
                    { id: env.DISCORD_GUILD_ID, type: 0, deny: '1024' },
                    { id: env.DISCORD_SUPPORT_ROLE_ID, type: 0, allow: '68608' }
                ]
            });
            ticket.messaging.discord = { channelId: channel.id, guildId: env.DISCORD_GUILD_ID };
            await env.AXIUM_KV.put(`discord_channel:${channel.id}`, ticket.id);
            await postDiscordChannelMessage(env, ticket, ticketSummary(ticket));
        } catch (error) {
            errors.push(`Discord: ${error.message}`);
        }
    }

    if (errors.length) ticket.messaging.errors = errors;
    await saveTicket(env, ticket);
    return ticket.messaging;
}

async function appendExternalTicketReply(env, ticket, { author, role, message }, source) {
    const createdAt = new Date().toISOString();
    ticket.notes.push({ type: 'note', message, author, role, createdAt, source });
    await saveTicket(env, ticket);
    await writeAuditEvent(env, { username: author, role }, 'ticket.external_reply', { ticketId: ticket.id, source });
    await broadcastTicketMessage(env, ticket, `[${ticket.id}] ${author}: ${message}`, source);
}

function decodeHex(value) {
    if (typeof value !== 'string' || !/^(?:[a-f0-9]{2})+$/i.test(value)) return null;
    return Uint8Array.from(value.match(/.{2}/g), byte => parseInt(byte, 16));
}

async function verifyDiscordRequest(request, bodyText, env) {
    const publicKey = decodeHex(env.DISCORD_PUBLIC_KEY);
    const signature = decodeHex(request.headers.get('X-Signature-Ed25519'));
    const timestamp = request.headers.get('X-Signature-Timestamp');
    if (!publicKey || !signature || !timestamp || Math.abs(Date.now() / 1000 - Number(timestamp)) > 300) return false;
    try {
        const key = await crypto.subtle.importKey('raw', publicKey, { name: 'Ed25519' }, false, ['verify']);
        return crypto.subtle.verify('Ed25519', key, signature, encoder.encode(`${timestamp}${bodyText}`));
    } catch (error) {
        console.error('Could not verify Discord interaction signature:', error);
        return false;
    }
}

async function updateDiscordInteraction(env, interaction, content) {
    const response = await fetch(`https://discord.com/api/v10/webhooks/${env.DISCORD_APPLICATION_ID}/${interaction.token}/messages/@original`, {
        method: 'PATCH',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ content: content.slice(0, 1900), allowed_mentions: { parse: [] } })
    });
    if (!response.ok) console.error('Could not update Discord reply command response:', response.status);
}

async function processDiscordReply(env, interaction) {
    try {
        const dedupeKey = `discord_interaction:${interaction.id}`;
        if (await env.AXIUM_KV.get(dedupeKey)) {
            await updateDiscordInteraction(env, interaction, 'This reply was already processed.');
            return;
        }
        const ticketId = await env.AXIUM_KV.get(`discord_channel:${interaction.channel_id}`);
        const ticket = ticketId ? await getTicket(env, ticketId) : null;
        const options = interaction.data.options || [];
        const requestedTicketId = options.find(option => option.name === 'ticket_id')?.value;
        const message = options.find(option => option.name === 'message')?.value;
        const supportRoleId = env.DISCORD_SUPPORT_ROLE_ID;
        const memberRoles = interaction.member?.roles || [];

        if (interaction.guild_id !== env.DISCORD_GUILD_ID || !supportRoleId || !memberRoles.includes(supportRoleId)) {
            await updateDiscordInteraction(env, interaction, 'Only members of the configured support role can reply to tickets.');
            return;
        }
        if (!ticket || ticket.id !== requestedTicketId || ticket.messaging?.discord?.channelId !== interaction.channel_id) {
            await updateDiscordInteraction(env, interaction, 'This channel is not linked to that ticket.');
            return;
        }
        if (typeof message !== 'string' || !message.trim() || message.length > 500) {
            await updateDiscordInteraction(env, interaction, 'Reply must be between 1 and 500 characters.');
            return;
        }
        const author = interaction.member?.user?.username || interaction.user?.username || 'Discord support';
        await appendExternalTicketReply(env, ticket, { author: `Discord: ${author}`, role: 'Tech Support', message: message.trim() }, 'discord');
        await env.AXIUM_KV.put(dedupeKey, '1', { expirationTtl: 7 * 24 * 60 * 60 });
        await updateDiscordInteraction(env, interaction, `Reply added to ${ticket.id} and sent to its Telegram topic.`);
    } catch (error) {
        console.error('Could not process Discord ticket reply:', error);
        await updateDiscordInteraction(env, interaction, 'Could not add the reply. Please retry or use the staff portal.');
    }
}

async function handleDiscordInteraction(request, env, context) {
    if (!env.DISCORD_PUBLIC_KEY || !env.DISCORD_BOT_TOKEN || !env.DISCORD_APPLICATION_ID || !env.DISCORD_GUILD_ID) {
        return json({ error: 'Discord integration is not configured.' }, 503);
    }
    const bodyText = await request.text();
    if (bodyText.length > 12000 || !await verifyDiscordRequest(request, bodyText, env)) return json({ error: 'Invalid Discord interaction signature.' }, 401);
    let interaction;
    try { interaction = JSON.parse(bodyText); } catch { return json({ error: 'Invalid Discord interaction body.' }, 400); }
    if (interaction.type === 1) return json({ type: 1 });
    if (interaction.type !== 2 || interaction.data?.name !== 'ticket-reply') return json({ error: 'Unsupported Discord interaction.' }, 400);
    context.waitUntil(processDiscordReply(env, interaction));
    return json({ type: 5, data: { flags: 64 } });
}

async function handleTelegramUpdate(request, env) {
    if (!env.TELEGRAM_BOT_TOKEN || !env.TELEGRAM_WEBHOOK_SECRET || !env.TELEGRAM_FORUM_CHAT_ID) {
        return json({ error: 'Telegram integration is not configured.' }, 503);
    }
    if (request.headers.get('X-Telegram-Bot-Api-Secret-Token') !== env.TELEGRAM_WEBHOOK_SECRET) return json({ error: 'Invalid Telegram webhook secret.' }, 401);
    let update;
    try { update = await readBody(request); } catch { return json({ error: 'Invalid Telegram update.' }, 400); }
    const message = update.message;
    if (!message?.message_thread_id || String(message.chat?.id) !== String(env.TELEGRAM_FORUM_CHAT_ID) || message.from?.is_bot) return json({ ok: true });
    const text = typeof message.text === 'string' ? message.text.trim() : '';
    if (!text) return json({ ok: true });
    const ticketId = await env.AXIUM_KV.get(`telegram_topic:${message.message_thread_id}`);
    const ticket = ticketId ? await getTicket(env, ticketId) : null;
    if (!ticket || ticket.messaging?.telegram?.chatId !== String(message.chat.id)) return json({ ok: true });
    const dedupeKey = `telegram_update:${update.update_id}`;
    if (await env.AXIUM_KV.get(dedupeKey)) return json({ ok: true });
    const author = message.from.username || [message.from.first_name, message.from.last_name].filter(Boolean).join(' ') || 'Telegram support';
    await appendExternalTicketReply(env, ticket, { author: `Telegram: ${author}`, role: 'Tech Support', message: text.slice(0, 500) }, 'telegram');
    await env.AXIUM_KV.put(dedupeKey, '1', { expirationTtl: 7 * 24 * 60 * 60 });
    return json({ ok: true });
}

async function setupMessagingIntegrations(env, origin) {
    const result = { discord: false, telegram: false };
    if (env.DISCORD_BOT_TOKEN && env.DISCORD_APPLICATION_ID && env.DISCORD_PUBLIC_KEY && env.DISCORD_GUILD_ID && env.DISCORD_SUPPORT_CATEGORY_ID && env.DISCORD_SUPPORT_ROLE_ID) {
        await discordApi(env, `/applications/${env.DISCORD_APPLICATION_ID}/guilds/${env.DISCORD_GUILD_ID}/commands`, 'PUT', [{
            name: 'ticket-reply',
            description: 'Reply to the ticket linked to this channel',
            options: [
                { name: 'ticket_id', description: 'Ticket ID shown in this channel', type: 3, required: true },
                { name: 'message', description: 'Reply text', type: 3, required: true, max_length: 500 }
            ]
        }]);
        result.discord = true;
    }
    if (env.TELEGRAM_BOT_TOKEN && env.TELEGRAM_WEBHOOK_SECRET && env.TELEGRAM_FORUM_CHAT_ID) {
        const webhookUrl = new URL('/api/telegram/webhook', origin).toString();
        await telegramApi(env, 'setWebhook', {
            url: webhookUrl,
            secret_token: env.TELEGRAM_WEBHOOK_SECRET,
            allowed_updates: ['message'],
            drop_pending_updates: false
        });
        result.telegram = true;
    }
    return result;
}

async function requestHandler(request, env) {
    if (!env.AXIUM_KV) return json({ error: 'Cloudflare KV binding AXIUM_KV is not configured.' }, 503);

    const url = new URL(request.url);
    const path = url.pathname.replace(/\/$/, '') || '/';
    const method = request.method.toUpperCase();

    if (method !== 'GET' && method !== 'HEAD' && method !== 'OPTIONS') assertSameOrigin(request);
    if (method === 'OPTIONS') return new Response(null, { status: 204, headers: { 'cache-control': 'no-store' } });

    if (path === '/api/config' && method === 'GET') {
        return json({ authMode: await getAuthMode(env), ssoConfigured: Boolean(getAccessDomain(env) && env.ACCESS_AUD) });
    }

    if (path === '/api/session' && method === 'GET') {
        const authMode = await getAuthMode(env);
        const account = await getSession(request, env);
        const setupRequired = await env.AXIUM_KV.get('system:initialized') !== 'true';
        const lockdown = await env.AXIUM_KV.get('system:lockdown') === 'true';
        return json({
            authenticated: Boolean(account),
            authMode,
            setupRequired,
            ...(account ? { user: account.username, email: account.email, role: account.role, lockdown } : {})
        });
    }

    if (path === '/api/bootstrap' && method === 'POST') {
        if (await getAuthMode(env) !== 'local') return json({ error: 'Switch to local authentication before initializing the first account.' }, 409);
        if (await env.AXIUM_KV.get('system:initialized') === 'true') return json({ error: 'Initial setup has already been completed.' }, 409);
        let body;
        try { body = await readBody(request); } catch { return json({ error: 'Invalid setup request.' }, 400); }
        const username = typeof body.username === 'string' ? body.username.trim().toLowerCase() : '';
        if (!USERNAME_PATTERN.test(username) || typeof body.password !== 'string' || body.password.length < 12 || body.password.length > 128) {
            return json({ error: 'Enter a valid username and password with 12 to 128 characters.' }, 400);
        }
        if (await env.AXIUM_KV.get(`username:${username}`)) return json({ error: 'That username is already registered.' }, 409);
        const password = await hashPassword(body.password);
        const accountKey = `user:local:${username}`;
        const account = { username, email: '', name: username, role: 'SUPER ADMIN', ...password, createdAt: new Date().toISOString() };
        await env.AXIUM_KV.put(accountKey, JSON.stringify(account));
        await env.AXIUM_KV.put(`username:${username}`, accountKey);
        await env.AXIUM_KV.put('system:initialized', 'true');
        await writeAuditEvent(env, account, 'system.bootstrapped');
        const session = await createSession(env, account, 'local');
        return json({ authenticated: true, authMode: 'local', user: username, email: account.email, role: account.role }, 201, { 'set-cookie': session.cookie });
    }

    if (path === '/api/login' && method === 'POST') {
        if (await getAuthMode(env) !== 'local') return json({ error: 'SSO is active. Continue with organization SSO.' }, 409);
        let body;
        try { body = await readBody(request); } catch { return json({ error: 'Invalid login request.' }, 400); }
        const username = typeof body.username === 'string' ? body.username.trim().toLowerCase() : '';
        const password = typeof body.password === 'string' ? body.password : '';
        const account = await getAccountByUsername(env, username);
        if (!account || !await verifyPassword(password, account)) return json({ error: 'Invalid username or password.' }, 401);
        const session = await createSession(env, account, 'local');
        return json({ authenticated: true, authMode: 'local', user: account.username, email: account.email, role: account.role, lockdown: await env.AXIUM_KV.get('system:lockdown') === 'true' }, 200, { 'set-cookie': session.cookie });
    }

    if (path === '/api/logout' && method === 'POST') {
        const token = readSessionCookie(request);
        if (token) {
            const tokenHash = encodeBase64(await crypto.subtle.digest('SHA-256', encoder.encode(token)));
            await env.AXIUM_KV.delete(`session:${tokenHash}`);
        }
        return json({ ok: true }, 200, { 'set-cookie': makeSessionCookie('', 0) });
    }

    if (path === '/api/sso/start' && method === 'GET') {
        if (await getAuthMode(env) !== 'sso') return json({ error: 'SSO is not active.' }, 409);
        const domain = getAccessDomain(env);
        const audience = typeof env.ACCESS_AUD === 'string' ? env.ACCESS_AUD.trim() : '';
        if (!domain || !audience) return json({ error: 'Cloudflare Access is not configured.' }, 503);
        const callbackUrl = new URL('/api/sso/callback', url.origin).toString();
        const loginUrl = new URL(`https://${domain}/cdn-cgi/access/login/${encodeURIComponent(audience)}`);
        loginUrl.searchParams.set('redirect_url', callbackUrl);
        return Response.redirect(loginUrl.toString(), 302);
    }

    if (path === '/api/sso/callback' && method === 'GET') {
        if (await getAuthMode(env) !== 'sso') return Response.redirect(new URL('/#portal', url.origin).toString(), 302);
        const identity = await getAccessIdentity(request, env);
        if (!identity) return json({ error: 'Cloudflare Access identity token is missing.' }, 401);
        const account = await getAccount(env, identity.email);
        if (!account) return json({ error: `SSO identity ${identity.email} has no portal role. Contact the Super Admin.` }, 403);
        const session = await createSession(env, account, 'sso', identity.expiresAt - Math.floor(Date.now() / 1000));
        return new Response(null, { status: 302, headers: { 'location': new URL('/#portal', url.origin).toString(), 'set-cookie': session.cookie, 'cache-control': 'no-store' } });
    }

    const account = await getSession(request, env);
    if (!account) return json({ error: 'Sign in to the portal to continue.' }, 401);

    if (path === '/api/users' && method === 'GET') {
        if (!requireRole(account, ['SUPER ADMIN'])) return json({ error: 'Super Admin role required.' }, 403);
        const users = (await listUsers(env)).map(user => ({ username: user.username, email: user.email, name: user.name, role: user.role, createdAt: user.createdAt }));
        return json({ users });
    }

    if (path === '/api/users' && method === 'POST') {
        if (!requireRole(account, ['SUPER ADMIN'])) return json({ error: 'Super Admin role required.' }, 403);
        let body;
        try { body = await readBody(request); } catch { return json({ error: 'Invalid account request.' }, 400); }
        const username = typeof body.username === 'string' ? body.username.trim().toLowerCase() : '';
        const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';
        const password = typeof body.password === 'string' ? body.password : '';
        if (!USERNAME_PATTERN.test(username)) return json({ error: 'Username must be 3 to 24 characters using letters, numbers, dots, underscores, or hyphens.' }, 400);
        if (!EMAIL_PATTERN.test(email) || email.length > 254) return json({ error: 'Enter a valid email address for the staff SSO identity.' }, 400);
        if (password.length < 12 || password.length > 128) return json({ error: 'Password must be 12 to 128 characters.' }, 400);
        if (!ROLES.includes(body.role) || body.role === 'SUPER ADMIN') return json({ error: 'Choose a valid non-super-admin role.' }, 400);
        if (await getAccount(env, email) || await env.AXIUM_KV.get(`username:${username}`)) return json({ error: 'That username or SSO email already has a portal account.' }, 409);
        const passwordFields = await hashPassword(password);
        const user = { username, email, name: email, role: body.role, ...passwordFields, createdAt: new Date().toISOString() };
        await env.AXIUM_KV.put(`user:${email}`, JSON.stringify(user));
        await env.AXIUM_KV.put(`username:${username}`, email);
        await writeAuditEvent(env, account, 'user.created', { username, email, role: user.role });
        return json({ user: { username, email, name: user.name, role: user.role, createdAt: user.createdAt } }, 201);
    }

    const userMatch = path.match(/^\/api\/users\/([^/]+)$/);
    if (userMatch && method === 'DELETE') {
        if (!requireRole(account, ['SUPER ADMIN'])) return json({ error: 'Super Admin role required.' }, 403);
        let email;
        try { email = decodeURIComponent(userMatch[1]).trim().toLowerCase(); } catch { return json({ error: 'Invalid email address.' }, 400); }
        const target = await getAccount(env, email);
        if (!target) return json({ error: 'Account not found.' }, 404);
        if (email === account.email || target.role === 'SUPER ADMIN') return json({ error: 'The active or protected Super Admin account cannot be deleted.' }, 400);
        await env.AXIUM_KV.delete(`user:${email}`);
        await env.AXIUM_KV.delete(`username:${target.username}`);
        await writeAuditEvent(env, account, 'user.deleted', { username: target.username, email, role: target.role });
        return json({ ok: true });
    }

    if (path === '/api/admin/auth-mode' && method === 'POST') {
        if (!requireRole(account, ['SUPER ADMIN'])) return json({ error: 'Super Admin role required.' }, 403);
        let body;
        try { body = await readBody(request); } catch { return json({ error: 'Invalid authentication mode request.' }, 400); }
        if (!['local', 'sso'].includes(body.mode)) return json({ error: 'Choose local or sso authentication.' }, 400);
        if (body.mode === 'sso' && (!getAccessDomain(env) || typeof env.ACCESS_AUD !== 'string' || !env.ACCESS_AUD.trim())) {
            return json({ error: 'Configure the Cloudflare Access team domain and application audience before enabling SSO.' }, 503);
        }
        if (body.mode === 'sso' && !account.email) return json({ error: 'The active administrator must have an SSO email before SSO can be enabled.' }, 400);
        const previousMode = await getAuthMode(env);
        if (previousMode !== body.mode) {
            await env.AXIUM_KV.put('system:auth_mode', body.mode);
            await writeAuditEvent(env, account, 'system.auth_mode_changed', { from: previousMode, to: body.mode });
        }
        return json({ authMode: body.mode, changed: previousMode !== body.mode });
    }

    if (path === '/api/admin/messaging/setup' && method === 'POST') {
        if (!requireRole(account, ['SUPER ADMIN'])) return json({ error: 'Super Admin role required.' }, 403);
        try {
            const configured = await setupMessagingIntegrations(env, url.origin);
            await writeAuditEvent(env, account, 'system.messaging_integrations_setup', configured);
            return json({ configured });
        } catch (error) {
            return json({ error: error.message }, 502);
        }
    }

    if (path === '/api/tickets' && method === 'GET') {
        return json({ tickets: await listTickets(env) });
    }

    if (path === '/api/tickets' && method === 'POST') {
        const lockdown = await env.AXIUM_KV.get('system:lockdown') === 'true';
        if (lockdown && !requireRole(account, ['SUPER ADMIN', 'Admin'])) return json({ error: 'Ticket creation is disabled during system lockdown.' }, 423);
        let body;
        try { body = await readBody(request); } catch { return json({ error: 'Invalid ticket request.' }, 400); }
        const title = typeof body.title === 'string' ? body.title.trim() : '';
        const desc = typeof body.desc === 'string' ? body.desc.trim() : '';
        const priorities = ['Low', 'Medium', 'High', 'Critical'];
        const categories = ['Digital Vault', 'Forensic Analysis', 'Network Security', 'Executive Advisory'];
        if (!title || title.length > 120 || !desc || desc.length > 2000) return json({ error: 'Title is required (max 120 characters) and description is required (max 2000 characters).' }, 400);
        if (!priorities.includes(body.priority) || !categories.includes(body.category)) return json({ error: 'Choose a valid priority and category.' }, 400);
        const ticket = {
            id: `AX-${crypto.randomUUID()}`,
            title,
            desc,
            category: body.category,
            priority: body.priority,
            status: 'OPEN',
            author: account.username,
            role: account.role,
            createdAt: new Date().toISOString(),
            notes: [{ type: 'created', message: 'Ticket created.', author: account.username, role: account.role, createdAt: new Date().toISOString() }]
        };
        await saveTicket(env, ticket);
        const messaging = await provisionTicketMessaging(env, ticket);
        await writeAuditEvent(env, account, 'ticket.created', { ticketId: ticket.id, priority: ticket.priority, category: ticket.category });
        return json({ ticket, messaging }, 201);
    }

    const ticketMatch = path.match(/^\/api\/tickets\/(AX-[a-f0-9-]+)$/i);
    if (ticketMatch && method === 'GET') {
        const ticket = await getTicket(env, ticketMatch[1]);
        return ticket ? json({ ticket }) : json({ error: 'Ticket not found.' }, 404);
    }
    if (ticketMatch && method === 'PATCH') {
        const ticket = await getTicket(env, ticketMatch[1]);
        if (!ticket) return json({ error: 'Ticket not found.' }, 404);
        let body;
        try { body = await readBody(request); } catch { return json({ error: 'Invalid ticket update.' }, 400); }
        const now = new Date().toISOString();
        if (body.status !== undefined) {
            if (!['IN_PROGRESS', 'RESOLVED'].includes(body.status)) return json({ error: 'Choose a valid ticket status.' }, 400);
            ticket.status = body.status;
            ticket.notes.push({ type: 'status', message: `Status changed to ${body.status}.`, author: account.username, role: account.role, createdAt: now });
        } else if (typeof body.note === 'string') {
            const note = body.note.trim();
            if (!note || note.length > 500) return json({ error: 'Notes must be 1 to 500 characters.' }, 400);
            ticket.notes.push({ type: 'note', message: note, author: account.username, role: account.role, createdAt: now });
        } else {
            return json({ error: 'No supported ticket update was provided.' }, 400);
        }
        await saveTicket(env, ticket);
        const eventMessage = body.status === undefined
            ? `[${ticket.id}] ${account.username}: ${body.note.trim()}`
            : `[${ticket.id}] Status changed to ${body.status} by ${account.username}.`;
        await broadcastTicketMessage(env, ticket, eventMessage);
        await writeAuditEvent(env, account, body.status === undefined ? 'ticket.note_added' : 'ticket.status_changed', {
            ticketId: ticket.id,
            ...(body.status === undefined ? {} : { status: body.status })
        });
        return json({ ticket });
    }
    if (ticketMatch && method === 'DELETE') {
        if (!requireRole(account, ['SUPER ADMIN', 'Admin'])) return json({ error: 'Admin role required to delete tickets.' }, 403);
        const key = `ticket:${ticketMatch[1]}`;
        if (!await env.AXIUM_KV.get(key)) return json({ error: 'Ticket not found.' }, 404);
        await env.AXIUM_KV.delete(key);
        await writeAuditEvent(env, account, 'ticket.deleted', { ticketId: ticketMatch[1] });
        return json({ ok: true });
    }

    if (path === '/api/admin/lockdown' && method === 'POST') {
        if (!requireRole(account, ['SUPER ADMIN'])) return json({ error: 'Super Admin role required.' }, 403);
        let body;
        try { body = await readBody(request); } catch { return json({ error: 'Invalid lockdown request.' }, 400); }
        if (typeof body.locked !== 'boolean') return json({ error: 'A boolean lockdown value is required.' }, 400);
        await env.AXIUM_KV.put('system:lockdown', String(body.locked));
        await writeAuditEvent(env, account, 'system.lockdown_changed', { locked: body.locked });
        return json({ locked: body.locked });
    }

    if (path === '/api/admin/purge-resolved' && method === 'POST') {
        if (!requireRole(account, ['SUPER ADMIN'])) return json({ error: 'Super Admin role required.' }, 403);
        const tickets = await listTickets(env);
        const resolved = tickets.filter(ticket => ticket.status === 'RESOLVED');
        await Promise.all(resolved.map(ticket => env.AXIUM_KV.delete(`ticket:${ticket.id}`)));
        await writeAuditEvent(env, account, 'tickets.resolved_purged', { count: resolved.length });
        return json({ deleted: resolved.length });
    }

    if (path === '/api/admin/audit' && method === 'GET') {
        if (!requireRole(account, ['SUPER ADMIN', 'Admin'])) return json({ error: 'Admin role required.' }, 403);
        const [tickets, users, lockdown, events] = await Promise.all([
            listTickets(env),
            listUsers(env),
            env.AXIUM_KV.get('system:lockdown'),
            listRecords(env.AXIUM_KV, 'audit:')
        ]);
        events.sort((left, right) => right.createdAt.localeCompare(left.createdAt));
        return json({
            generatedAt: new Date().toISOString(),
            exportedBy: account.username,
            role: account.role,
            summary: { ticketsCount: tickets.length, userCount: users.length, lockdown: lockdown === 'true' },
            events
        });
    }

    return json({ error: 'API endpoint not found.' }, 404);
}

export default {
    async fetch(request, env, context) {
        const path = new URL(request.url).pathname;
        if (path === '/api/discord/interactions' && request.method === 'POST') {
            return handleDiscordInteraction(request, env, context);
        }
        if (path === '/api/telegram/webhook' && request.method === 'POST') {
            try {
                return await handleTelegramUpdate(request, env);
            } catch (error) {
                console.error('Could not process Telegram update:', error);
                return json({ error: 'Could not process Telegram update.' }, 500);
            }
        }
        if (path.startsWith('/api/')) {
            try {
                return await requestHandler(request, env);
            } catch (error) {
                console.error('Axium API request failed:', error);
                return json({ error: error.status ? error.message : 'The request could not be completed.' }, error.status || 500);
            }
        }
        return env.ASSETS.fetch(request);
    }
};
