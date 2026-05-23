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

This repo includes `render.yaml` for Render. Create a new Render Blueprint from the GitHub repository, or create a Web Service manually:

- Build command: `npm install`
- Start command: `npm start`
- Runtime: Node 18+

The prototype uses `data/wbv-db.json` for persistence. For production, replace this with PostgreSQL before onboarding real patients, doctors, pharmacies, or payment data.

## Production Next Steps

- Move persistence from JSON to PostgreSQL.
- Add password hashing and JWT/session expiry.
- Add secure file storage for documents, such as S3-compatible storage.
- Integrate Paystack or Flutterwave for real payments.
- Add provider email/SMS notifications.
- Add NDPR-aligned retention and deletion workflows.
