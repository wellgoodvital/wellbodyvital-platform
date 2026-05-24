# WellBodyVital Security Baseline

This is the minimum backend security posture before customer-app or admin-app integration.

## API Versioning

Production integrations should call the versioned namespace:

```txt
/api/v1/*
```

The older `/api/*` routes remain temporarily for demo compatibility.

## Authentication

- Passwords are hashed with Node `crypto.scrypt`.
- Login returns a short-lived access token and a refresh token.
- Access tokens expire after 15 minutes by default.
- Refresh tokens expire after 7 days by default.
- Refresh tokens expire after 30 minutes of inactivity by default.
- Refresh token rotation is enforced: refresh revokes the previous refresh token and issues a new one.
- Logout can revoke the refresh token when the client sends it in the request body.
- Every protected route uses `auth` and role-gated routes use `allow(...)`.

Required production environment variables:

```txt
TOKEN_SECRET=<long random signing secret>
ENCRYPTION_SECRET=<long random field-encryption secret>
ACCESS_TOKEN_TTL_MS=900000
REFRESH_TOKEN_TTL_MS=604800000
REFRESH_IDLE_TTL_MS=1800000
```

## Frontend Safety Rules

- Do not place API keys in browser JavaScript.
- Frontends should call same-origin routes such as `/api/v1/customer/profile`; they should not call raw infrastructure IP addresses or provider APIs directly.
- Payment, document storage, email, SMS, and database credentials stay server-side.
- Payment checkout should be created server-side; payment verification and webhooks must happen server-side.

## Data Protection

- TLS protects data in transit through Netlify or the chosen production host.
- Sensitive medical questionnaire fields are encrypted with AES-256-GCM before storage in the prototype datastore.
- The server decrypts sensitive fields only when returning them to an authorized user flow.
- Audit logs redact secrets, tokens, passwords, and IP fields.
- API responses include a request ID for support correlation without exposing client network details.

## Middleware Included

- `auth`: bearer-token authentication.
- `allow`: role-based access control.
- `rateLimit`: in-memory throttling for login and refresh endpoints.
- `audit`: sensitive action logging with redaction.
- `encryptField` / `decryptField`: field-level encryption helpers.
- `/api/v1` request rewriting: versioned API namespace.

## Production Hardening Still Required

- Move persistence from JSON or `/tmp` storage to PostgreSQL or Supabase.
- Store refresh tokens in the production database and enforce revocation there.
- Add a strict CORS allowlist once mobile/web app origins are finalized.
- Add schema validation for every request body.
- Add object-level authorization checks for every patient, consultation, prescription, and order record.
- Use private object storage with signed URLs for documents.
- Add malware scanning and file type validation for uploads.
- Integrate Paystack or Flutterwave using hosted checkout or tokenized flows.
