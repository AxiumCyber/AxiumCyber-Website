# Axium Cyber Website

Axium Cyber's single-page website and staff portal. Cloudflare Workers serves the site and API; Cloudflare KV stores staff accounts, sessions, tickets, and portal settings.

## Requirements

- A Cloudflare account with Workers enabled
- Node.js and npm
- Wrangler CLI (run with `npx wrangler`)

The page loads Tailwind CSS, Font Awesome, and Google Fonts from CDNs, so those assets require an internet connection.

## Configure Cloudflare

1. Create a KV namespace:

	```sh
	npx wrangler kv namespace create AXIUM_KV
	```

2. Copy the namespace ID from Wrangler's output into `wrangler.jsonc`, replacing `REPLACE_WITH_KV_NAMESPACE_ID`.
3. Log in to Cloudflare and create a one-time bootstrap secret:

	```sh
	npx wrangler login
	npx wrangler secret put AXIUM_BOOTSTRAP_SECRET
	```

	Enter a long, unique setup key when Wrangler prompts. Keep it private; it is only used to initialize the first Super Admin.

## Run and deploy

Run the site and Worker locally:

```sh
npx wrangler dev
```

Deploy to Cloudflare Workers:

```sh
npx wrangler deploy
```

Open the deployed site and choose **Staff & Admin Portal**. On first visit, use the setup form with the bootstrap key and a new 12+ character admin password. The initial username is `admin`. After setup, remove the bootstrap secret:

```sh
npx wrangler secret delete AXIUM_BOOTSTRAP_SECRET
```

The Super Admin can create accounts with the Admin, Tech Support, Moderator, or Staff role and remove non-super-admin accounts. Ticket and administrative permissions are enforced by the Worker, not just by the browser UI.

## Data and security

KV stores password hashes (PBKDF2, not plaintext passwords), expiring server-side sessions, individual ticket records, and portal settings. The session is an `HttpOnly`, `Secure`, `SameSite=Strict` cookie. Data is shared by users of this deployment and is not kept in browser `localStorage`.

Cloudflare KV is eventually consistent and is not a transactional database. It is suitable for this lightweight portal, but simultaneous edits to the same ticket or account can race. For strict consistency, high-volume ticketing, or regulated data, use a transactional database such as D1 and add an appropriate audit/backup policy.

The forensic scanner and terminal panels on the site are interface demos; they do not contact a real threat-intelligence or scanning service. Do not treat their output as security findings.
