# WellBodyVital Platform

Backend API and back office dashboard for a Nigeria-focused medical weight loss subscription platform.

## What Is Included

- Customer mobile-style web app at `/`
- Back office dashboard at `/admin`
- Express API with role-based access control
- Demo accounts for Super Admin, Operations, Doctor, Pharmacy, and Patient roles
- Provider credential upload and review workflow
- Doctor consultation, medical decision, prescription, and secure messaging workflows
- Pharmacy order, inventory, cold-chain, fulfillment, and refill workflows
- Payment, subscription, payout, refund, reporting, and audit-log workflows
- Local JSON datastore for prototype/demo mode
- Versioned `/api/v1` routes, expiring access tokens, refresh-token rotation, password hashing, audit redaction, and encrypted medical questionnaire payloads

## Demo Login

All demo accounts use:

```txt
password123
```

Accounts:

```txt
super@wellbodyvital.com
ops@wellbodyvital.com
doctor@wellbodyvital.com
pharmacy@wellbodyvital.com
patient@wellbodyvital.com
```

## API Security

Production integrations should use the versioned namespace:

```txt
/api/v1/*
```

Login returns a short-lived access token and refresh token. Protected routes require:

```txt
Authorization: Bearer <accessToken>
```

See [docs/security-baseline.md](docs/security-baseline.md) for the security middleware, token expiry, refresh behavior, encryption notes, and production hardening checklist.

## Local Development

```bash
npm install
npm start
```

Open:

```txt
http://localhost:3000
http://localhost:3000/admin
```

## Cloud Deployment

### Netlify Free Deployment

Netlify is the recommended free deployment option for this demo.

1. Import the GitHub repo into Netlify.
2. Use these settings:

```txt
Build command: npm install
Publish directory: public
Functions directory: netlify/functions
```

3. Add this environment variable:

```txt
TOKEN_SECRET=replace-with-a-long-random-secret
```

The included `netlify.toml` routes the Express backend through a Netlify Function, so these paths work after deployment:

```txt
/
/admin
/api/*
```

Important: Netlify Functions do not provide durable local disk storage. The current JSON database is demo-only on Netlify. Move persistence to PostgreSQL or Supabase before using the system with real users.

### Render Deployment

This repo includes `render.yaml` for Render. Create a new Render Blueprint from the GitHub repository, or create a Web Service manually:

- Build command: `npm install`
- Start command: `npm start`
- Runtime: Node 18+

The prototype uses `data/wbv-db.json` for persistence. For production, replace this with PostgreSQL before onboarding real patients, doctors, pharmacies, or payment data.

## Production Next Steps

- Move persistence from JSON to PostgreSQL.
- Keep password hashing and token expiry enabled with strong production secrets.
- Replace demo JSON persistence with PostgreSQL/Supabase.
- Add strict request-body schema validation and production CORS allowlists.
- Add secure file storage for documents, such as S3-compatible storage.
- Integrate Paystack or Flutterwave for real payments.
- Add provider email/SMS notifications.
- Add NDPR-aligned retention and deletion workflows.
