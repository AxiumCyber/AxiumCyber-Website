const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const ROLES = ['SUPER ADMIN', 'Admin', 'Tech Support', 'Moderator', 'Staff'];
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
    return { email, name: typeof claims.name === 'string' ? claims.name : email };
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

async function getSession(request, env) {
    const identity = await getAccessIdentity(request, env);
    if (!identity) return null;
    const account = await getAccount(env, identity.email);
    return account ? { ...account, username: account.email, identity } : null;
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

async function requestHandler(request, env) {
    if (!env.AXIUM_KV) return json({ error: 'Cloudflare KV binding AXIUM_KV is not configured.' }, 503);

    const url = new URL(request.url);
    const path = url.pathname.replace(/\/$/, '') || '/';
    const method = request.method.toUpperCase();

    if (method !== 'GET' && method !== 'HEAD' && method !== 'OPTIONS') assertSameOrigin(request);
    if (method === 'OPTIONS') return new Response(null, { status: 204, headers: { 'cache-control': 'no-store' } });

    if (path === '/api/config' && method === 'GET') {
        const domain = getAccessDomain(env);
        if (!domain || typeof env.ACCESS_AUD !== 'string' || !env.ACCESS_AUD.trim()) {
            return json({ error: 'Cloudflare Access is not configured. Set ACCESS_TEAM_DOMAIN and ACCESS_AUD.' }, 503);
        }
        return json({
            loginUrl: `https://${domain}/cdn-cgi/access/login/${encodeURIComponent(env.ACCESS_AUD.trim())}`,
            logoutUrl: `https://${domain}/cdn-cgi/access/logout`
        });
    }

    const identity = await getAccessIdentity(request, env);

    if (path === '/api/session' && method === 'GET') {
        const setupRequired = await env.AXIUM_KV.get('system:initialized') !== 'true';
        const account = identity ? await getAccount(env, identity.email) : null;
        const lockdown = await env.AXIUM_KV.get('system:lockdown') === 'true';
        return json({
            authenticated: Boolean(account),
            ssoAuthenticated: Boolean(identity),
            identityEmail: identity?.email || null,
            identityName: identity?.name || null,
            setupRequired,
            ...(account ? { user: account.email, role: account.role, lockdown } : {})
        });
    }

    if (path === '/api/bootstrap' && method === 'POST') {
        if (!identity) return json({ error: 'Sign in through your Cloudflare Access identity provider first.' }, 401);
        if (!env.AXIUM_BOOTSTRAP_SECRET) return json({ error: 'Initial setup is disabled. Configure AXIUM_BOOTSTRAP_SECRET first.' }, 503);
        if (await env.AXIUM_KV.get('system:initialized') === 'true') return json({ error: 'Initial setup has already been completed.' }, 409);
        let body;
        try { body = await readBody(request); } catch { return json({ error: 'Invalid setup request.' }, 400); }
        if (typeof body.setupSecret !== 'string' || body.setupSecret !== env.AXIUM_BOOTSTRAP_SECRET) return json({ error: 'Invalid setup key.' }, 401);
        if (!await env.AXIUM_KV.get('system:initialized') && await getAccount(env, identity.email)) {
            return json({ error: 'This SSO identity already has a portal account.' }, 409);
        }
        const account = { email: identity.email, name: identity.name, role: 'SUPER ADMIN', createdAt: new Date().toISOString() };
        await env.AXIUM_KV.put(`user:${identity.email}`, JSON.stringify(account));
        await env.AXIUM_KV.put('system:initialized', 'true');
        await writeAuditEvent(env, account, 'system.bootstrapped');
        return json({ authenticated: true, user: account.email, role: account.role, lockdown: false }, 201);
    }

    if (!identity) return json({ error: 'Sign in through Cloudflare Access to continue.' }, 401);
    const account = await getAccount(env, identity.email);
    if (!account) return json({ error: `SSO identity ${identity.email} is not assigned a portal role. Contact your Super Admin.` }, 403);
    account.username = account.email;

    if (path === '/api/users' && method === 'GET') {
        if (!requireRole(account, ['SUPER ADMIN'])) return json({ error: 'Super Admin role required.' }, 403);
        const users = (await listUsers(env)).map(user => ({ email: user.email, name: user.name, role: user.role, createdAt: user.createdAt }));
        return json({ users });
    }

    if (path === '/api/users' && method === 'POST') {
        if (!requireRole(account, ['SUPER ADMIN'])) return json({ error: 'Super Admin role required.' }, 403);
        let body;
        try { body = await readBody(request); } catch { return json({ error: 'Invalid account request.' }, 400); }
        const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';
        if (!EMAIL_PATTERN.test(email) || email.length > 254) return json({ error: 'Enter a valid email address for the staff SSO identity.' }, 400);
        if (!ROLES.includes(body.role) || body.role === 'SUPER ADMIN') return json({ error: 'Choose a valid non-super-admin role.' }, 400);
        if (await getAccount(env, email)) return json({ error: 'That SSO email already has a portal role.' }, 409);
        const user = { email, name: email, role: body.role, createdAt: new Date().toISOString() };
        await env.AXIUM_KV.put(`user:${email}`, JSON.stringify(user));
        await writeAuditEvent(env, account, 'user.created', { email, role: user.role });
        return json({ user: { email, name: user.name, role: user.role, createdAt: user.createdAt } }, 201);
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
        await writeAuditEvent(env, account, 'user.deleted', { email, role: target.role });
        return json({ ok: true });
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
        await writeAuditEvent(env, account, 'ticket.created', { ticketId: ticket.id, priority: ticket.priority, category: ticket.category });
        return json({ ticket }, 201);
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
    async fetch(request, env) {
        if (new URL(request.url).pathname.startsWith('/api/')) {
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
