const COOKIE_NAME = '__Host-axium_session';
const SESSION_TTL_SECONDS = 60 * 60 * 8;
const PASSWORD_ITERATIONS = 120000;
const USERNAME_PATTERN = /^[a-z0-9._-]{3,24}$/;
const ROLES = ['SUPER ADMIN', 'Admin', 'Tech Support', 'Moderator', 'Staff'];
const encoder = new TextEncoder();

function json(data, status = 200, headers = {}) {
    return new Response(JSON.stringify(data), {
        status,
        headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...headers }
    });
}

function cookieHeader(token, maxAge = SESSION_TTL_SECONDS) {
    return `${COOKIE_NAME}=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}`;
}

function readCookie(request, name) {
    const cookieHeaderValue = request.headers.get('Cookie') || '';
    const match = cookieHeaderValue.split(';').map(part => part.trim()).find(part => part.startsWith(`${name}=`));
    return match ? match.slice(name.length + 1) : null;
}

function toBase64(bytes) {
    return btoa(String.fromCharCode(...new Uint8Array(bytes)));
}

function fromBase64(value) {
    return Uint8Array.from(atob(value), character => character.charCodeAt(0));
}

async function sha256(value) {
    return crypto.subtle.digest('SHA-256', encoder.encode(value));
}

async function hashPassword(password, salt = crypto.getRandomValues(new Uint8Array(16))) {
    const key = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']);
    const hash = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: PASSWORD_ITERATIONS }, key, 256);
    return { salt: toBase64(salt), passwordHash: toBase64(hash) };
}

async function verifyPassword(password, account) {
    const result = await hashPassword(password, fromBase64(account.salt));
    const expected = fromBase64(account.passwordHash);
    const actual = fromBase64(result.passwordHash);
    return expected.length === actual.length && expected.reduce((difference, byte, index) => difference | (byte ^ actual[index]), 0) === 0;
}

async function readBody(request) {
    const text = await request.text();
    if (text.length > 24000) throw new Error('Request body is too large.');
    return text ? JSON.parse(text) : {};
}

function validUsername(value) {
    return typeof value === 'string' && USERNAME_PATTERN.test(value.trim().toLowerCase());
}

function validPassword(value) {
    return typeof value === 'string' && value.length >= 12 && value.length <= 128;
}

async function getAccount(env, username) {
    if (!validUsername(username)) return null;
    return env.AXIUM_KV.get(`user:${username.trim().toLowerCase()}`, 'json');
}

async function createSession(env, username) {
    const token = toBase64(crypto.getRandomValues(new Uint8Array(32))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    const tokenHash = toBase64(await sha256(token));
    const expiresAt = Date.now() + SESSION_TTL_SECONDS * 1000;
    await env.AXIUM_KV.put(`session:${tokenHash}`, JSON.stringify({ username, expiresAt }), { expirationTtl: SESSION_TTL_SECONDS });
    return token;
}

async function getSession(request, env) {
    const token = readCookie(request, COOKIE_NAME);
    if (!token) return null;
    const tokenHash = toBase64(await sha256(token));
    const session = await env.AXIUM_KV.get(`session:${tokenHash}`, 'json');
    if (!session || session.expiresAt <= Date.now()) {
        await env.AXIUM_KV.delete(`session:${tokenHash}`);
        return null;
    }
    const account = await getAccount(env, session.username);
    if (!account) {
        await env.AXIUM_KV.delete(`session:${tokenHash}`);
        return null;
    }
    return { username: account.username, role: account.role };
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

async function requestHandler(request, env) {
    if (!env.AXIUM_KV) return json({ error: 'Cloudflare KV binding AXIUM_KV is not configured.' }, 503);

    const url = new URL(request.url);
    const path = url.pathname.replace(/\/$/, '') || '/';
    const method = request.method.toUpperCase();

    if (method !== 'GET' && method !== 'HEAD' && method !== 'OPTIONS') assertSameOrigin(request);
    if (method === 'OPTIONS') return new Response(null, { status: 204, headers: { 'cache-control': 'no-store' } });

    if (path === '/api/bootstrap' && method === 'GET') {
        const initialized = await env.AXIUM_KV.get('system:initialized');
        return json({ setupRequired: initialized !== 'true' });
    }

    if (path === '/api/bootstrap' && method === 'POST') {
        if (!env.AXIUM_BOOTSTRAP_SECRET) return json({ error: 'Initial setup is disabled. Configure AXIUM_BOOTSTRAP_SECRET first.' }, 503);
        if (await env.AXIUM_KV.get('system:initialized') === 'true') return json({ error: 'Initial setup has already been completed.' }, 409);
        let body;
        try { body = await readBody(request); } catch { return json({ error: 'Invalid setup request.' }, 400); }
        if (typeof body.setupSecret !== 'string' || body.setupSecret !== env.AXIUM_BOOTSTRAP_SECRET) return json({ error: 'Invalid setup key.' }, 401);
        if (!validPassword(body.password)) return json({ error: 'Choose a password with 12 to 128 characters.' }, 400);
        const password = await hashPassword(body.password);
        const account = { username: 'admin', role: 'SUPER ADMIN', ...password, createdAt: new Date().toISOString() };
        await env.AXIUM_KV.put('user:admin', JSON.stringify(account));
        await env.AXIUM_KV.put('system:initialized', 'true');
        const token = await createSession(env, account.username);
        return json({ authenticated: true, user: account.username, role: account.role, lockdown: false }, 201, { 'set-cookie': cookieHeader(token) });
    }

    if (path === '/api/session' && method === 'GET') {
        const setupRequired = await env.AXIUM_KV.get('system:initialized') !== 'true';
        const account = await getSession(request, env);
        const lockdown = await env.AXIUM_KV.get('system:lockdown') === 'true';
        return json(account ? { authenticated: true, user: account.username, role: account.role, lockdown } : { authenticated: false, setupRequired });
    }

    if (path === '/api/login' && method === 'POST') {
        let body;
        try { body = await readBody(request); } catch { return json({ error: 'Invalid login request.' }, 400); }
        const username = typeof body.username === 'string' ? body.username.trim().toLowerCase() : '';
        const password = typeof body.password === 'string' ? body.password : '';
        if (!validUsername(username) || !password) return json({ error: 'Invalid username or password.' }, 401);
        const account = await getAccount(env, username);
        if (!account || !await verifyPassword(password, account)) return json({ error: 'Invalid username or password.' }, 401);
        const token = await createSession(env, account.username);
        return json({ authenticated: true, user: account.username, role: account.role, lockdown: await env.AXIUM_KV.get('system:lockdown') === 'true' }, 200, { 'set-cookie': cookieHeader(token) });
    }

    if (path === '/api/logout' && method === 'POST') {
        const token = readCookie(request, COOKIE_NAME);
        if (token) await env.AXIUM_KV.delete(`session:${toBase64(await sha256(token))}`);
        return json({ ok: true }, 200, { 'set-cookie': cookieHeader('', 0) });
    }

    const account = await getSession(request, env);
    if (!account) return json({ error: 'Authentication required.' }, 401);

    if (path === '/api/users' && method === 'GET') {
        if (!requireRole(account, ['SUPER ADMIN'])) return json({ error: 'Super Admin role required.' }, 403);
        const users = (await listUsers(env)).map(user => ({ username: user.username, role: user.role, createdAt: user.createdAt }));
        return json({ users });
    }

    if (path === '/api/users' && method === 'POST') {
        if (!requireRole(account, ['SUPER ADMIN'])) return json({ error: 'Super Admin role required.' }, 403);
        let body;
        try { body = await readBody(request); } catch { return json({ error: 'Invalid account request.' }, 400); }
        const username = typeof body.username === 'string' ? body.username.trim().toLowerCase() : '';
        if (!validUsername(username)) return json({ error: 'Username must be 3 to 24 characters using letters, numbers, dots, underscores, or hyphens.' }, 400);
        if (!validPassword(body.password)) return json({ error: 'Password must be 12 to 128 characters.' }, 400);
        if (!ROLES.includes(body.role) || body.role === 'SUPER ADMIN') return json({ error: 'Choose a valid non-super-admin role.' }, 400);
        if (await getAccount(env, username)) return json({ error: 'That username already exists.' }, 409);
        const password = await hashPassword(body.password);
        const user = { username, role: body.role, ...password, createdAt: new Date().toISOString() };
        await env.AXIUM_KV.put(`user:${username}`, JSON.stringify(user));
        return json({ user: { username, role: user.role, createdAt: user.createdAt } }, 201);
    }

    const userMatch = path.match(/^\/api\/users\/([a-z0-9._-]+)$/);
    if (userMatch && method === 'DELETE') {
        if (!requireRole(account, ['SUPER ADMIN'])) return json({ error: 'Super Admin role required.' }, 403);
        const username = decodeURIComponent(userMatch[1]);
        const target = await getAccount(env, username);
        if (!target) return json({ error: 'Account not found.' }, 404);
        if (username === account.username || target.role === 'SUPER ADMIN') return json({ error: 'The active or protected Super Admin account cannot be deleted.' }, 400);
        await env.AXIUM_KV.delete(`user:${username}`);
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
        return json({ ticket });
    }
    if (ticketMatch && method === 'DELETE') {
        if (!requireRole(account, ['SUPER ADMIN', 'Admin'])) return json({ error: 'Admin role required to delete tickets.' }, 403);
        const key = `ticket:${ticketMatch[1]}`;
        if (!await env.AXIUM_KV.get(key)) return json({ error: 'Ticket not found.' }, 404);
        await env.AXIUM_KV.delete(key);
        return json({ ok: true });
    }

    if (path === '/api/admin/lockdown' && method === 'POST') {
        if (!requireRole(account, ['SUPER ADMIN'])) return json({ error: 'Super Admin role required.' }, 403);
        let body;
        try { body = await readBody(request); } catch { return json({ error: 'Invalid lockdown request.' }, 400); }
        if (typeof body.locked !== 'boolean') return json({ error: 'A boolean lockdown value is required.' }, 400);
        await env.AXIUM_KV.put('system:lockdown', String(body.locked));
        return json({ locked: body.locked });
    }

    if (path === '/api/admin/purge-resolved' && method === 'POST') {
        if (!requireRole(account, ['SUPER ADMIN'])) return json({ error: 'Super Admin role required.' }, 403);
        const tickets = await listTickets(env);
        const resolved = tickets.filter(ticket => ticket.status === 'RESOLVED');
        await Promise.all(resolved.map(ticket => env.AXIUM_KV.delete(`ticket:${ticket.id}`)));
        return json({ deleted: resolved.length });
    }

    if (path === '/api/admin/audit' && method === 'GET') {
        if (!requireRole(account, ['SUPER ADMIN', 'Admin'])) return json({ error: 'Admin role required.' }, 403);
        const [tickets, users, lockdown] = await Promise.all([listTickets(env), listUsers(env), env.AXIUM_KV.get('system:lockdown')]);
        return json({ timestamp: new Date().toISOString(), exportedBy: account.username, role: account.role, ticketsCount: tickets.length, userCount: users.length, lockdown: lockdown === 'true', status: 'OK' });
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
