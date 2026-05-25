/**
 * WellBodyVital Back Office + Customer API
 * Nigeria-focused medical weight loss subscription platform.
 *
 * Run: npm start
 */

const crypto = require('crypto');
const express = require('express');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const IS_SERVERLESS = Boolean(process.env.WBV_SERVERLESS || process.env.VERCEL || process.env.AWS_LAMBDA_FUNCTION_NAME);
const APP_ROOT = process.env.APP_ROOT || (IS_SERVERLESS ? process.cwd() : __dirname);
const DB_PATH = process.env.DB_PATH || (IS_SERVERLESS ? path.join('/tmp', 'wbv-db.json') : path.join(APP_ROOT, 'data', 'wbv-db.json'));
const TOKEN_SECRET = process.env.TOKEN_SECRET || 'wellbodyvital-local-demo-secret';
const ENCRYPTION_SECRET = process.env.ENCRYPTION_SECRET || TOKEN_SECRET;
const ACCESS_TOKEN_TTL_MS = Number(process.env.ACCESS_TOKEN_TTL_MS || 15 * 60 * 1000);
const REFRESH_TOKEN_TTL_MS = Number(process.env.REFRESH_TOKEN_TTL_MS || 7 * 24 * 60 * 60 * 1000);
const REFRESH_IDLE_TTL_MS = Number(process.env.REFRESH_IDLE_TTL_MS || 30 * 60 * 1000);
const PUBLIC_BASE_URL = process.env.PUBLIC_BASE_URL || process.env.URL || `http://localhost:${PORT}`;
const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY || '';
const rateBuckets = new Map();

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

app.use((req, res, next) => {
  req.requestId = req.headers['x-request-id'] || id('req');
  res.setHeader('X-Request-ID', req.requestId);
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader('Cache-Control', 'no-store');
  next();
});

app.use((req, res, next) => {
  if (req.url.startsWith('/api/v1/')) {
    req.url = req.url.replace(/^\/api\/v1/, '/api');
  }
  next();
});

app.use(express.static(path.join(APP_ROOT, 'public'), {
  maxAge: '30d',
  etag: true,
}));

function now() {
  return new Date().toISOString();
}

function id(prefix) {
  return `${prefix}_${crypto.randomBytes(5).toString('hex')}`;
}

function ensureDb() {
  fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
  if (!fs.existsSync(DB_PATH)) {
    fs.writeFileSync(DB_PATH, JSON.stringify(seedData(), null, 2));
  }
}

function readDb() {
  ensureDb();
  const db = JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
  return migrateDb(db);
}

function writeDb(db) {
  fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2));
}

function migrateDb(db) {
  const seeded = seedData();
  ['promoCodes', 'referrals', 'emailEvents'].forEach((key) => {
    if (!Array.isArray(db[key])) db[key] = seeded[key] || [];
  });
  db.users = (db.users || []).map((user) => ({ ...user, referralCode: user.referralCode || referralCodeFor(user.name || user.email) }));
  db.settings = { ...seeded.settings, ...(db.settings || {}) };
  return db;
}

function publicUser(user) {
  if (!user) return null;
  const { password, passwordHash, ...safe } = user;
  return safe;
}

function passwordHash(password, salt = crypto.randomBytes(16).toString('base64url')) {
  const hash = crypto.scryptSync(String(password), salt, 64).toString('base64url');
  return `scrypt$${salt}$${hash}`;
}

function verifyPassword(user, password) {
  if (user.passwordHash?.startsWith('scrypt$')) {
    const [, salt, expected] = user.passwordHash.split('$');
    const actual = crypto.scryptSync(String(password), salt, 64).toString('base64url');
    return crypto.timingSafeEqual(Buffer.from(actual), Buffer.from(expected));
  }
  return user.password === password;
}

const PASSWORD_BLOCKLIST = ['password', 'password123', 'qwerty', 'qwerty123', '12345678', '123456789', '11111111', 'admin123', 'letmein', 'welcome', 'wellbodyvital', 'nigeria'];
function passwordPolicy(password, context = {}) {
  const value = String(password || '');
  const lower = value.toLowerCase();
  const issues = [];
  if (value.length < 8) issues.push('Use at least 8 characters.');
  if (value.length > 128) issues.push('Use 128 characters or fewer.');
  if (PASSWORD_BLOCKLIST.some((word) => lower.includes(word))) issues.push('Avoid common or easily guessed passwords.');
  if (context.email && lower.includes(String(context.email).split('@')[0].toLowerCase())) issues.push('Do not include your email name.');
  if (context.name && String(context.name).trim().split(/\s+/).some((part) => part.length > 2 && lower.includes(part.toLowerCase()))) issues.push('Do not include your name.');
  return { ok: issues.length === 0, issues };
}

function validateEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(email || ''));
}

function normalizeVerificationMethod(method) {
  const allowed = ['email', 'whatsapp', 'sms', 'auth_app'];
  return allowed.includes(method) ? method : 'email';
}

function isWithin(value, min, max) {
  const number = money(value);
  return Number.isFinite(number) && number >= min && number <= max;
}

function tokenHash(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

function encryptionKey() {
  return crypto.createHash('sha256').update(ENCRYPTION_SECRET).digest();
}

function encryptField(value) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', encryptionKey(), iv);
  const plaintext = JSON.stringify(value ?? null);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return {
    alg: 'aes-256-gcm',
    iv: iv.toString('base64url'),
    tag: cipher.getAuthTag().toString('base64url'),
    ciphertext: encrypted.toString('base64url'),
  };
}

function decryptField(payload) {
  if (!payload?.ciphertext) return null;
  const decipher = crypto.createDecipheriv('aes-256-gcm', encryptionKey(), Buffer.from(payload.iv, 'base64url'));
  decipher.setAuthTag(Buffer.from(payload.tag, 'base64url'));
  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(payload.ciphertext, 'base64url')),
    decipher.final(),
  ]).toString('utf8');
  return JSON.parse(decrypted);
}

function signToken(userId, type = 'access', ttlMs = ACCESS_TOKEN_TTL_MS, extra = {}) {
  const issuedAt = Date.now();
  const payload = Buffer.from(JSON.stringify({
    userId,
    type,
    jti: id(type === 'refresh' ? 'rt' : 'at'),
    iat: issuedAt,
    exp: issuedAt + ttlMs,
    ...extra,
  })).toString('base64url');
  const signature = crypto.createHmac('sha256', TOKEN_SECRET).update(payload).digest('base64url');
  return `wbv_${payload}.${signature}`;
}

function verifyToken(token, expectedType = 'access') {
  if (!token?.startsWith('wbv_')) return null;
  const [payload, signature] = token.slice(4).split('.');
  if (!payload || !signature) return null;
  const expected = crypto.createHmac('sha256', TOKEN_SECRET).update(payload).digest('base64url');
  if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) return null;
  try {
    const claims = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    if (claims.type !== expectedType) return null;
    if (Date.now() > claims.exp) return null;
    return claims;
  } catch (error) {
    return null;
  }
}

function issueTokenPair(db, user) {
  const accessToken = signToken(user.id, 'access', ACCESS_TOKEN_TTL_MS);
  const refreshToken = signToken(user.id, 'refresh', REFRESH_TOKEN_TTL_MS);
  const claims = verifyToken(refreshToken, 'refresh');
  db.refreshTokens = db.refreshTokens || [];
  db.refreshTokens.push({
    id: claims.jti,
    userId: user.id,
    tokenHash: tokenHash(refreshToken),
    createdAt: now(),
    lastUsedAt: now(),
    expiresAt: new Date(claims.exp).toISOString(),
    revokedAt: null,
  });
  return {
    token: accessToken,
    accessToken,
    refreshToken,
    tokenType: 'Bearer',
    expiresIn: Math.floor(ACCESS_TOKEN_TTL_MS / 1000),
    refreshExpiresIn: Math.floor(REFRESH_TOKEN_TTL_MS / 1000),
  };
}

function redactSensitive(value) {
  if (!value || typeof value !== 'object') return value;
  const blocked = new Set(['password', 'passwordHash', 'token', 'accessToken', 'refreshToken', 'authorization', 'apiKey', 'secret', 'ip']);
  return Object.fromEntries(Object.entries(value).map(([key, item]) => [
    key,
    blocked.has(key) ? '[redacted]' : item,
  ]));
}

function rateLimit(name, limit, windowMs) {
  return (req, res, next) => {
    const key = `${name}:${req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown'}`;
    const bucket = rateBuckets.get(key) || { count: 0, resetAt: Date.now() + windowMs };
    if (Date.now() > bucket.resetAt) {
      bucket.count = 0;
      bucket.resetAt = Date.now() + windowMs;
    }
    bucket.count += 1;
    rateBuckets.set(key, bucket);
    if (bucket.count > limit) {
      return res.status(429).json({ error: 'Too many requests. Please wait and try again.', requestId: req.requestId });
    }
    next();
  };
}

function audit(db, actor, action, entityType, entityId, details = {}) {
  db.auditLogs.unshift({
    id: id('audit'),
    actorUserId: actor?.id || 'system',
    actorRole: actor?.role || 'system',
    action,
    entityType,
    entityId,
    details: redactSensitive(details),
    createdAt: now(),
  });
}

function auth(req, res, next) {
  const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  const session = verifyToken(token, 'access');
  if (!session) return res.status(401).json({ error: 'Authentication required or token expired', requestId: req.requestId });
  const db = readDb();
  const user = db.users.find((item) => item.id === session.userId && item.status !== 'disabled');
  if (!user) return res.status(401).json({ error: 'Session user not found', requestId: req.requestId });
  req.db = db;
  req.user = user;
  req.token = token;
  next();
}

function allow(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Insufficient role permissions', requestId: req.requestId });
    }
    next();
  };
}

function saveAndSend(req, res, payload, status = 200) {
  writeDb(req.db);
  res.status(status).json(payload);
}

function byId(collection, itemId) {
  return collection.find((item) => item.id === itemId);
}

function money(amount) {
  return Number(amount || 0);
}

function referralCodeFor(name) {
  const prefix = String(name || 'WBV').replace(/[^a-z0-9]/gi, '').slice(0, 4).toUpperCase() || 'WBV';
  return `${prefix}${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
}

function referralLinkFor(user) {
  return `${PUBLIC_BASE_URL.replace(/\/$/, '')}/?ref=${encodeURIComponent(user.referralCode || user.id)}`;
}

function normalizeCurrency(currency) {
  const value = String(currency || 'NGN').toUpperCase();
  return ['NGN', 'USD'].includes(value) ? value : null;
}

function paymentSubunit(amount) {
  return Math.round(money(amount) * 100);
}

function discountAmountFor(code, plan, amount) {
  if (!code || !plan) return 0;
  const appliesTo = code.appliesToPlanIds || [];
  if (appliesTo.length && !appliesTo.includes(plan.id) && !appliesTo.includes(plan.slug)) return 0;
  if (code.type === 'percent') return Math.min(amount, Math.round((amount * money(code.value)) / 100));
  return Math.min(amount, money(code.value));
}

function summaryStats(db) {
  const successfulPayments = db.payments.filter((payment) => payment.status === 'paid');
  const revenue = successfulPayments.reduce((sum, payment) => sum + money(payment.amount), 0);
  const commission = successfulPayments.reduce((sum, payment) => sum + money(payment.platformCommission), 0);
  const pendingCredentials = db.credentials.filter((doc) => doc.status === 'pending').length;
  const activeSubscriptions = db.subscriptions.filter((sub) => sub.status === 'active').length;
  return {
    revenue,
    commission,
    activeSubscriptions,
    users: db.users.length,
    pendingCredentials,
    openTickets: db.supportTickets.filter((ticket) => ticket.status !== 'closed').length,
    prescriptionsAwaitingFulfillment: db.prescriptions.filter((rx) => rx.status === 'approved').length,
  };
}

function currentSubscriptionFor(db, userId) {
  return db.subscriptions.find((sub) => sub.userId === userId && sub.status === 'active')
    || db.subscriptions.find((sub) => sub.userId === userId)
    || null;
}

function questionnaireForResponse(questionnaire) {
  if (!questionnaire) return null;
  return {
    ...questionnaire,
    medicalPayload: questionnaire.encryptedMedicalPayload ? decryptField(questionnaire.encryptedMedicalPayload) : null,
    encryptedMedicalPayload: undefined,
  };
}

function seedData() {
  const createdAt = now();
  const users = [
    { id: 'usr_super', role: 'super_admin', name: 'Ade WellBody', email: 'super@wellbodyvital.com', phone: '+2348000000001', country: 'Nigeria', status: 'active', referralCode: 'ADEWBV', passwordHash: passwordHash('password123'), createdAt },
    { id: 'usr_ops', role: 'operations', name: 'Operations Lead', email: 'ops@wellbodyvital.com', phone: '+2348000000002', country: 'Nigeria', status: 'active', referralCode: 'OPSWBV', passwordHash: passwordHash('password123'), createdAt },
    { id: 'usr_doctor', role: 'doctor', name: 'Dr. Kemi Adeyemi', email: 'doctor@wellbodyvital.com', phone: '+2348000000003', country: 'Nigeria', status: 'pending_verification', referralCode: 'DOCWBV', passwordHash: passwordHash('password123'), createdAt },
    { id: 'usr_pharmacy', role: 'pharmacy', name: 'MedPlus Lekki Pharmacy', email: 'pharmacy@wellbodyvital.com', phone: '+2348000000004', country: 'Nigeria', status: 'pending_verification', referralCode: 'PHRWBV', passwordHash: passwordHash('password123'), createdAt },
    { id: 'usr_patient', role: 'patient', name: 'Amara Okafor', email: 'patient@wellbodyvital.com', phone: '+2348000000005', country: 'Nigeria', status: 'active', referralCode: 'AMARA25', passwordHash: passwordHash('password123'), createdAt },
    { id: 'usr_patient2', role: 'patient', name: 'Tunde Balogun', email: 'tunde@example.com', phone: '+2348000000006', country: 'Nigeria', status: 'active', referralCode: 'TUNDE25', passwordHash: passwordHash('password123'), createdAt },
  ];

  const plans = [
    { id: 'plan_starter', slug: 'starter', name: 'Starter', price: 15000, currency: 'NGN', billingCycle: 'monthly', doctorFee: 0, pharmacyAllocation: 0, platformCommissionRate: 0.18, status: 'active', features: ['Personalised meal plan', 'Custom fitness programme', 'Weekly coaching session', 'Supplement guidance', 'Progress tracking'] },
    { id: 'plan_pro', slug: 'pro', name: 'Pro', price: 35000, currency: 'NGN', billingCycle: 'monthly', doctorFee: 10000, pharmacyAllocation: 0, platformCommissionRate: 0.20, status: 'active', features: ['Everything in Starter', 'Doctor consultation', 'Medical eligibility screening', 'Prescription access if approved', 'Priority support'] },
    { id: 'plan_premium', slug: 'premium', name: 'Premium', price: 65000, currency: 'NGN', billingCycle: 'monthly', doctorFee: 15000, pharmacyAllocation: 25000, platformCommissionRate: 0.22, status: 'active', features: ['Everything in Pro', 'GLP-1 access if clinically eligible', 'NAFDAC pharmacy delivery', 'Monthly follow-up', 'Refill management'] },
  ];

  return {
    users,
    plans,
    subscriptions: [
      { id: 'sub_001', userId: 'usr_patient', planId: 'plan_pro', status: 'active', startedAt: createdAt, nextBillingAt: '2026-06-23T09:00:00.000Z', renewalCount: 2 },
      { id: 'sub_002', userId: 'usr_patient2', planId: 'plan_premium', status: 'past_due', startedAt: createdAt, nextBillingAt: '2026-05-27T09:00:00.000Z', renewalCount: 1 },
    ],
    payments: [
      { id: 'pay_001', userId: 'usr_patient', subscriptionId: 'sub_001', type: 'subscription', amount: 35000, currency: 'NGN', status: 'paid', channel: 'paystack', reference: 'WBV-2026-48291', doctorFee: 10000, pharmacyFee: 0, platformCommission: 7000, createdAt },
      { id: 'pay_002', userId: 'usr_patient2', subscriptionId: 'sub_002', type: 'subscription', amount: 65000, currency: 'NGN', status: 'failed', channel: 'card', reference: 'WBV-2026-48292', doctorFee: 15000, pharmacyFee: 25000, platformCommission: 14300, createdAt },
    ],
    questionnaires: [
      { id: 'q_001', userId: 'usr_patient', status: 'submitted', heightCm: 166, weightKg: 92, bmi: 33.4, encryptedMedicalPayload: encryptField({ goals: ['Lose 18kg', 'Improve energy', 'Lower cravings'], conditions: ['Hypertension'], medications: ['Amlodipine'], allergies: ['None'] }), submittedAt: createdAt },
      { id: 'q_002', userId: 'usr_patient2', status: 'submitted', heightCm: 178, weightKg: 112, bmi: 35.3, encryptedMedicalPayload: encryptField({ goals: ['Reduce BMI', 'Improve sleep'], conditions: ['Prediabetes'], medications: [], allergies: ['Penicillin'] }), submittedAt: createdAt },
    ],
    doctorProfiles: [
      { id: 'doc_prof_001', userId: 'usr_doctor', specialty: 'Endocrinology and metabolic medicine', mdcnNumber: 'MDCN/NG/452198', activePractice: true, verificationStatus: 'pending', approvedAt: null, rejectedReason: null, patientsAssigned: ['usr_patient'], consultationRate: 10000 },
    ],
    pharmacyProfiles: [
      { id: 'pharm_prof_001', userId: 'usr_pharmacy', pcnNumber: 'PCN/LAG/204882', premisesLicense: 'LAG-PREM-98211', coldChainCertified: true, verificationStatus: 'pending', approvedAt: null, rejectedReason: null, coverageStates: ['Lagos', 'Ogun', 'Oyo'], fulfillmentFeeRate: 0.12 },
    ],
    credentials: [
      { id: 'cred_001', ownerUserId: 'usr_doctor', ownerRole: 'doctor', type: 'MDCN license', fileName: 'mdcn-license-kemi.pdf', url: '/uploads/demo/mdcn-license-kemi.pdf', status: 'pending', reviewedBy: null, reviewedAt: null, notes: '', uploadedAt: createdAt },
      { id: 'cred_002', ownerUserId: 'usr_doctor', ownerRole: 'doctor', type: 'Government ID', fileName: 'nin-kemi.pdf', url: '/uploads/demo/nin-kemi.pdf', status: 'pending', reviewedBy: null, reviewedAt: null, notes: '', uploadedAt: createdAt },
      { id: 'cred_003', ownerUserId: 'usr_pharmacy', ownerRole: 'pharmacy', type: 'PCN license', fileName: 'pcn-medplus.pdf', url: '/uploads/demo/pcn-medplus.pdf', status: 'pending', reviewedBy: null, reviewedAt: null, notes: '', uploadedAt: createdAt },
      { id: 'cred_004', ownerUserId: 'usr_pharmacy', ownerRole: 'pharmacy', type: 'Premises license', fileName: 'premises-medplus.pdf', url: '/uploads/demo/premises-medplus.pdf', status: 'pending', reviewedBy: null, reviewedAt: null, notes: '', uploadedAt: createdAt },
    ],
    consultations: [
      { id: 'consult_001', patientId: 'usr_patient', doctorId: 'usr_doctor', questionnaireId: 'q_001', status: 'under_review', eligibility: 'pending', recommendation: '', followUpAt: '2026-05-30T10:00:00.000Z', sideEffects: [], createdAt },
    ],
    prescriptions: [
      { id: 'rx_001', patientId: 'usr_patient', doctorId: 'usr_doctor', pharmacyId: 'usr_pharmacy', consultationId: 'consult_001', medication: 'Semaglutide starter protocol', dosage: 'Clinician supervised titration', status: 'draft', auditTrail: [{ at: createdAt, by: 'usr_doctor', action: 'draft_created' }], issuedAt: null },
    ],
    orders: [
      { id: 'ord_001', patientId: 'usr_patient', prescriptionId: 'rx_001', pharmacyId: 'usr_pharmacy', status: 'prescription_received', coldChainRequired: true, coldChainConfirmed: false, deliveryAddress: 'Victoria Island, Lagos', proofOfFulfillmentUrl: '', updatedAt: createdAt },
    ],
    deliveries: [
      { id: 'del_001', orderId: 'ord_001', courier: 'GIG Logistics', trackingCode: 'GIG-WBV-001', status: 'pending_pickup', deliveredAt: null, failedReason: null },
    ],
    messages: [
      { id: 'msg_001', threadId: 'thread_usr_patient_usr_doctor', fromUserId: 'usr_doctor', toUserId: 'usr_patient', text: 'Please share your most recent blood pressure readings and fasting glucose if available.', secure: true, readAt: null, createdAt },
    ],
    notifications: [
      { id: 'note_001', userId: 'usr_patient', type: 'doctor_message', title: 'Dr. Kemi sent you a message', body: 'Tap to read the consultation note.', read: false, createdAt },
    ],
    promoCodes: [
      { id: 'promo_001', code: 'WELCOME10', type: 'percent', value: 10, description: '10% off first subscription', appliesToPlanIds: ['plan_starter', 'plan_pro', 'plan_premium'], active: true, maxRedemptions: 500, redemptionCount: 0, startsAt: createdAt, expiresAt: null, createdAt },
      { id: 'promo_002', code: 'PREMIUM5000', type: 'fixed', value: 5000, description: 'N5,000 Premium discount', appliesToPlanIds: ['plan_premium'], active: true, maxRedemptions: 250, redemptionCount: 0, startsAt: createdAt, expiresAt: null, createdAt },
    ],
    referrals: [
      { id: 'ref_001', referrerUserId: 'usr_patient', referredUserId: 'usr_patient2', code: 'AMARA25', status: 'qualified', rewardAmount: 2500, currency: 'NGN', createdAt, paidAt: null },
    ],
    emailEvents: [
      { id: 'email_001', userId: 'usr_patient', to: 'patient@wellbodyvital.com', template: 'welcome_verification', status: 'queued', provider: 'not_configured', createdAt },
    ],
    payouts: [
      { id: 'payout_001', recipientUserId: 'usr_doctor', role: 'doctor', amount: 10000, currency: 'NGN', status: 'pending', sourcePaymentIds: ['pay_001'], dueAt: '2026-05-30T09:00:00.000Z', paidAt: null },
      { id: 'payout_002', recipientUserId: 'usr_pharmacy', role: 'pharmacy', amount: 25000, currency: 'NGN', status: 'pending', sourcePaymentIds: [], dueAt: '2026-05-30T09:00:00.000Z', paidAt: null },
    ],
    supportTickets: [
      { id: 'ticket_001', userId: 'usr_patient2', assignedTo: 'usr_ops', priority: 'high', subject: 'Failed card payment', status: 'open', messages: ['Customer card failed during Premium renewal.'], escalated: false, createdAt },
    ],
    inventory: [
      { id: 'inv_001', pharmacyId: 'usr_pharmacy', medication: 'Semaglutide starter pens', quantity: 18, coldChain: true, nafdacDocStatus: 'verified', updatedAt: createdAt },
      { id: 'inv_002', pharmacyId: 'usr_pharmacy', medication: 'Alcohol swabs', quantity: 250, coldChain: false, nafdacDocStatus: 'not_required', updatedAt: createdAt },
    ],
    consentRecords: [
      { id: 'consent_001', userId: 'usr_patient', type: 'Medical Data Consent', version: '2026.1', accepted: true, acceptedAt: createdAt },
      { id: 'consent_002', userId: 'usr_patient', type: 'Telehealth Consent', version: '2026.1', accepted: true, acceptedAt: createdAt },
    ],
    progressLogs: [
      { id: 'prog_001', userId: 'usr_patient', weightKg: 92, bmi: 33.4, waistCm: 101, notes: 'Starting baseline', loggedAt: '2026-05-01T09:00:00.000Z' },
      { id: 'prog_002', userId: 'usr_patient', weightKg: 89.8, bmi: 32.6, waistCm: 98, notes: 'First follow-up', loggedAt: '2026-05-15T09:00:00.000Z' },
      { id: 'prog_003', userId: 'usr_patient', weightKg: 88.5, bmi: 32.1, waistCm: 96, notes: 'Steady progress', loggedAt: '2026-05-23T09:00:00.000Z' },
    ],
    auditLogs: [
      { id: 'audit_seed', actorUserId: 'system', actorRole: 'system', action: 'seed_created', entityType: 'database', entityId: 'wbv-db', details: { source: 'server bootstrap' }, createdAt },
    ],
    refreshTokens: [],
    settings: {
      platformName: 'WellBodyVital',
      country: 'Nigeria',
      currency: 'NGN',
      doctorAutoAssign: false,
      pharmacyAutoAssign: false,
      ndprRetentionYears: 7,
      supportEmail: 'support@wellbodyvital.com',
      payoutDay: 'Friday',
      usdExchangeRate: 1500,
      referralRewardAmount: 2500,
    },
  };
}

function providerDashboard(db, role, userId) {
  if (role === 'doctor') {
    const consultations = db.consultations.filter((item) => item.doctorId === userId);
    const patientIds = [...new Set(consultations.map((item) => item.patientId))];
    return {
      profile: db.doctorProfiles.find((profile) => profile.userId === userId),
      patients: db.users.filter((user) => patientIds.includes(user.id)).map(publicUser),
      consultations,
      messages: db.messages.filter((message) => message.fromUserId === userId || message.toUserId === userId),
      payouts: db.payouts.filter((payout) => payout.recipientUserId === userId),
      prescriptions: db.prescriptions.filter((rx) => rx.doctorId === userId),
    };
  }
  const orders = db.orders.filter((order) => order.pharmacyId === userId);
  return {
    profile: db.pharmacyProfiles.find((profile) => profile.userId === userId),
    prescriptions: db.prescriptions.filter((rx) => rx.pharmacyId === userId),
    orders,
    inventory: db.inventory.filter((item) => item.pharmacyId === userId),
    payouts: db.payouts.filter((payout) => payout.recipientUserId === userId),
  };
}

app.get('/admin', (req, res) => {
  res.sendFile(path.join(APP_ROOT, 'public', 'backoffice.html'));
});

app.post('/api/auth/register', (req, res) => {
  const db = readDb();
  const role = req.body.role || 'patient';
  const allowedRoles = ['patient', 'doctor', 'pharmacy'];
  if (!allowedRoles.includes(role)) return res.status(400).json({ error: 'Unsupported self-registration role' });
  if (!validateEmail(req.body.email)) return res.status(400).json({ error: 'A valid email address is required' });
  const fullName = String(req.body.name || `${req.body.firstName || ''} ${req.body.lastName || ''}`).trim();
  if (!fullName) return res.status(400).json({ error: 'Full name is required' });
  const passwordCheck = passwordPolicy(req.body.password, { email: req.body.email, name: fullName });
  if (!passwordCheck.ok) return res.status(400).json({ error: `Password is not strong enough. ${passwordCheck.issues.join(' ')}` });
  if (db.users.some((user) => user.email.toLowerCase() === String(req.body.email || '').toLowerCase())) {
    return res.status(409).json({ error: 'Email already registered' });
  }
  const verificationMethod = normalizeVerificationMethod(req.body.verificationMethod);
  const user = {
    id: id('usr'),
    role,
    name: fullName,
    email: req.body.email,
    phone: req.body.phone || '',
    country: req.body.country || 'Nigeria',
    referralCode: referralCodeFor(fullName),
    referredByCode: req.body.referralCode ? String(req.body.referralCode).trim().toUpperCase() : null,
    verificationMethod,
    verificationPriority: verificationMethod === 'sms' ? ['sms'] : verificationMethod === 'whatsapp' ? ['whatsapp', 'sms'] : [verificationMethod],
    emailVerifiedAt: null,
    phoneVerifiedAt: null,
    status: role === 'patient' ? 'active' : 'pending_verification',
    passwordHash: passwordHash(req.body.password),
    createdAt: now(),
  };
  db.users.push(user);
  db.notifications = db.notifications || [];
  db.emailEvents = db.emailEvents || [];
  db.referrals = db.referrals || [];
  db.notifications.unshift({
    id: id('note'),
    userId: user.id,
    type: 'account_created',
    title: 'Welcome to WellBodyVital',
    body: 'Your account has been created. Please verify your email address to keep your health record secure.',
    read: false,
    createdAt: now(),
  });
  db.emailEvents.unshift({
    id: id('email'),
    userId: user.id,
    to: user.email,
    template: 'welcome_verification',
    status: 'queued',
    provider: process.env.EMAIL_PROVIDER || 'not_configured',
    createdAt: now(),
  });
  const referrer = user.referredByCode ? db.users.find((item) => item.referralCode === user.referredByCode) : null;
  if (referrer && referrer.id !== user.id) {
    db.referrals.unshift({
      id: id('ref'),
      referrerUserId: referrer.id,
      referredUserId: user.id,
      code: user.referredByCode,
      status: 'pending_subscription',
      rewardAmount: money(db.settings?.referralRewardAmount || 2500),
      currency: 'NGN',
      createdAt: now(),
      paidAt: null,
    });
  }
  if (role === 'doctor') {
    db.doctorProfiles.push({
      id: id('doc_prof'),
      userId: user.id,
      specialty: req.body.specialty || '',
      mdcnNumber: req.body.mdcnNumber || '',
      activePractice: Boolean(req.body.activePractice),
      verificationStatus: 'pending',
      approvedAt: null,
      rejectedReason: null,
      patientsAssigned: [],
      consultationRate: money(req.body.consultationRate || 10000),
    });
  }
  if (role === 'pharmacy') {
    db.pharmacyProfiles.push({
      id: id('pharm_prof'),
      userId: user.id,
      pcnNumber: req.body.pcnNumber || '',
      premisesLicense: req.body.premisesLicense || '',
      coldChainCertified: Boolean(req.body.coldChainCertified),
      verificationStatus: 'pending',
      approvedAt: null,
      rejectedReason: null,
      coverageStates: req.body.coverageStates || [],
      fulfillmentFeeRate: 0.12,
    });
  }
  audit(db, user, 'register', 'user', user.id, { role });
  writeDb(db);
  res.status(201).json({ success: true, user: publicUser(user), verificationQueued: true, emailQueued: true });
});

app.post('/api/auth/login', rateLimit('auth:login', 10, 15 * 60 * 1000), (req, res) => {
  const db = readDb();
  const user = db.users.find((item) => item.email.toLowerCase() === String(req.body.email || '').toLowerCase());
  if (!user || !verifyPassword(user, req.body.password)) return res.status(401).json({ error: 'Invalid email or password', requestId: req.requestId });
  if (!user.passwordHash) {
    user.passwordHash = passwordHash(req.body.password);
    delete user.password;
  }
  const tokens = issueTokenPair(db, user);
  audit(db, user, 'login', 'user', user.id, { requestId: req.requestId });
  writeDb(db);
  res.json({ success: true, ...tokens, user: publicUser(user) });
});

app.post('/api/auth/refresh', rateLimit('auth:refresh', 30, 15 * 60 * 1000), (req, res) => {
  const db = readDb();
  const refreshToken = req.body.refreshToken || (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  const claims = verifyToken(refreshToken, 'refresh');
  if (!claims) return res.status(401).json({ error: 'Refresh token expired or invalid', requestId: req.requestId });
  const stored = (db.refreshTokens || []).find((item) => item.id === claims.jti && item.tokenHash === tokenHash(refreshToken));
  if (!stored || stored.revokedAt) return res.status(401).json({ error: 'Refresh token revoked', requestId: req.requestId });
  if (Date.now() - new Date(stored.lastUsedAt).getTime() > REFRESH_IDLE_TTL_MS) {
    stored.revokedAt = now();
    writeDb(db);
    return res.status(401).json({ error: 'Refresh token expired after inactivity', requestId: req.requestId });
  }
  const user = db.users.find((item) => item.id === claims.userId && item.status !== 'disabled');
  if (!user) return res.status(401).json({ error: 'Session user not found', requestId: req.requestId });
  stored.revokedAt = now();
  const tokens = issueTokenPair(db, user);
  audit(db, user, 'token_refreshed', 'user', user.id, { requestId: req.requestId });
  writeDb(db);
  res.json({ success: true, ...tokens, user: publicUser(user) });
});

app.post('/api/auth/logout', auth, (req, res) => {
  if (req.body?.refreshToken) {
    const claims = verifyToken(req.body.refreshToken, 'refresh');
    const stored = (req.db.refreshTokens || []).find((item) => item.id === claims?.jti);
    if (stored) stored.revokedAt = now();
  }
  audit(req.db, req.user, 'logout', 'user', req.user.id);
  saveAndSend(req, res, { success: true });
});

app.get('/api/auth/me', auth, (req, res) => {
  res.json({ user: publicUser(req.user) });
});

app.post('/api/auth/forgot', (req, res) => res.json({ success: true, message: 'Reset email queued when email service is connected' }));

app.get('/api/schema', auth, allow('super_admin', 'operations'), (req, res) => {
  res.json({
    tables: Object.keys(req.db).filter((key) => Array.isArray(req.db[key])),
    settings: Object.keys(req.db.settings),
    note: 'The prototype uses data/wbv-db.json. The collections map directly to future SQL or document tables.',
  });
});

app.get('/api/user/profile', auth, (req, res) => {
  const subscription = currentSubscriptionFor(req.db, req.user.id);
  const plan = subscription ? byId(req.db.plans, subscription.planId) : null;
  res.json({ user: publicUser(req.user), subscription, plan });
});

app.put('/api/user/profile', auth, (req, res) => {
  Object.assign(req.user, {
    name: req.body.name ?? req.user.name,
    phone: req.body.phone ?? req.user.phone,
  });
  audit(req.db, req.user, 'profile_update', 'user', req.user.id);
  saveAndSend(req, res, { success: true, user: publicUser(req.user) });
});

app.get('/api/customer/dashboard', auth, allow('patient'), (req, res) => {
  const subscription = currentSubscriptionFor(req.db, req.user.id);
  const plan = subscription ? byId(req.db.plans, subscription.planId) : null;
  const questionnaire = questionnaireForResponse(req.db.questionnaires.find((item) => item.userId === req.user.id));
  const progressLogs = (req.db.progressLogs || []).filter((item) => item.userId === req.user.id);
  const consultations = req.db.consultations.filter((item) => item.patientId === req.user.id).map((item) => {
    const doctor = byId(req.db.users, item.doctorId);
    const profile = req.db.doctorProfiles.find((profileItem) => profileItem.userId === item.doctorId);
    return {
      ...item,
      doctorName: doctor?.name || 'Assigned Doctor',
      specialty: profile?.specialty || 'Medical review',
      scheduledAt: item.followUpAt,
      notes: item.recommendation || '',
    };
  });
  const prescriptions = req.db.prescriptions.filter((item) => item.patientId === req.user.id);
  const orders = req.db.orders.filter((item) => item.patientId === req.user.id);
  const notifications = req.db.notifications.filter((item) => item.userId === req.user.id);
  res.json({
    user: publicUser(req.user),
    subscription,
    plan,
    questionnaire,
    progressLogs,
    consultations,
    prescriptions,
    orders,
    notifications,
    settings: {
      usdExchangeRate: money(req.db.settings?.usdExchangeRate || 1500),
      referralRewardAmount: money(req.db.settings?.referralRewardAmount || 2500),
    },
  });
});

app.get('/api/plans', (req, res) => {
  const db = readDb();
  res.json({ plans: db.plans.filter((plan) => plan.status === 'active') });
});

app.post('/api/address/verify', auth, (req, res) => {
  const country = String(req.body.country || '').trim();
  const state = String(req.body.state || '').trim();
  const address = String(req.body.address || '').trim();
  const words = address.split(/\s+/).filter(Boolean);
  const hasNumber = /\d/.test(address);
  const hasStreetDetail = words.length >= 4 || address.includes(',');
  const verified = Boolean(country && state && address.length >= 12 && hasNumber && hasStreetDetail);
  audit(req.db, req.user, 'address_verification_checked', 'user', req.user.id, {
    country,
    state,
    verified,
    verificationLevel: 'format',
  });
  saveAndSend(req, res, {
    verified,
    verificationLevel: 'format',
    message: verified
      ? 'Address format verified. External geocoding can be connected through the server when provider credentials are added.'
      : 'Add a house number, street name, area/city, and state so delivery teams can confirm the address.',
  });
});

app.post('/api/promo/validate', auth, (req, res) => {
  req.db.promoCodes = req.db.promoCodes || [];
  const codeValue = String(req.body.code || '').trim().toUpperCase();
  const plan = byId(req.db.plans, req.body.planId) || req.db.plans.find((item) => item.slug === req.body.plan);
  const promo = req.db.promoCodes.find((item) => item.code === codeValue && item.active);
  if (!promo) return res.status(404).json({ error: 'Promo or referral code was not found' });
  if (promo.expiresAt && new Date(promo.expiresAt).getTime() < Date.now()) return res.status(400).json({ error: 'Promo code has expired' });
  if (promo.maxRedemptions && promo.redemptionCount >= promo.maxRedemptions) return res.status(400).json({ error: 'Promo code has reached its redemption limit' });
  const amount = money(req.body.amount || plan?.price);
  const discount = discountAmountFor(promo, plan, amount);
  if (!discount) return res.status(400).json({ error: 'Promo code does not apply to this subscription plan' });
  audit(req.db, req.user, 'promo_validated', 'promo_code', promo.id, { code: promo.code, planId: plan?.id, discount });
  saveAndSend(req, res, { valid: true, promo: { ...promo, discountAmount: discount }, discountAmount: discount, finalAmount: Math.max(0, amount - discount) });
});

app.get('/api/referrals/me', auth, (req, res) => {
  req.db.referrals = req.db.referrals || [];
  if (!req.user.referralCode) req.user.referralCode = referralCodeFor(req.user.name);
  const referrals = req.db.referrals.filter((item) => item.referrerUserId === req.user.id);
  const earnings = referrals.filter((item) => item.status === 'qualified').reduce((sum, item) => sum + money(item.rewardAmount), 0);
  saveAndSend(req, res, {
    code: req.user.referralCode,
    link: referralLinkFor(req.user),
    rewardAmount: money(req.db.settings?.referralRewardAmount || 2500),
    earnings,
    referrals,
  });
});

app.post('/api/subscription', auth, (req, res) => {
  const plan = byId(req.db.plans, req.body.planId) || req.db.plans.find((item) => item.slug === req.body.plan);
  if (!plan) return res.status(404).json({ error: 'Plan not found' });
  const subscription = {
    id: id('sub'),
    userId: req.user.id,
    planId: plan.id,
    status: req.body.status === 'pending_payment' ? 'pending_payment' : 'active',
    startedAt: now(),
    nextBillingAt: new Date(Date.now() + 30 * 86400000).toISOString(),
    renewalCount: 0,
  };
  req.db.subscriptions.push(subscription);
  audit(req.db, req.user, 'subscription_created', 'subscription', subscription.id, { planId: plan.id });
  saveAndSend(req, res, { success: true, subscription });
});

app.post('/api/payment/initiate', auth, async (req, res) => {
  const channels = ['paystack'];
  if (!isWithin(req.body.amount, 1, 10000000)) return res.status(400).json({ error: 'A valid payment amount is required' });
  if (req.body.channel && !channels.includes(req.body.channel)) return res.status(400).json({ error: 'Unsupported payment channel' });
  const currency = normalizeCurrency(req.body.currency);
  if (!currency) return res.status(400).json({ error: 'Currency must be NGN or USD' });
  const reference = `WBV-${Date.now()}`;
  const payment = {
    id: id('pay'),
    userId: req.user.id,
    subscriptionId: req.body.subscriptionId || null,
    type: req.body.type || 'subscription',
    amount: money(req.body.amount),
    currency,
    status: 'pending',
    channel: 'paystack',
    reference,
    promoCode: req.body.promoCode || null,
    doctorFee: money(req.body.doctorFee),
    pharmacyFee: money(req.body.pharmacyFee),
    platformCommission: money(req.body.platformCommission),
    createdAt: now(),
  };
  req.db.payments.push(payment);
  audit(req.db, req.user, 'payment_initiated', 'payment', payment.id, { reference, currency });
  if (!PAYSTACK_SECRET_KEY) {
    saveAndSend(req, res, {
      reference,
      payment,
      checkoutStatus: 'requires_configuration',
      authorizationUrl: null,
      message: 'Paystack secret key is not configured on the server. Add PAYSTACK_SECRET_KEY to enable hosted checkout.',
    });
    return;
  }
  try {
    const response = await fetch('https://api.paystack.co/transaction/initialize', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${PAYSTACK_SECRET_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        email: req.user.email,
        amount: paymentSubunit(payment.amount),
        currency,
        reference,
        callback_url: `${PUBLIC_BASE_URL.replace(/\/$/, '')}/payment-callback`,
        metadata: {
          userId: req.user.id,
          subscriptionId: payment.subscriptionId,
          paymentId: payment.id,
          promoCode: payment.promoCode,
        },
      }),
    });
    const result = await response.json();
    if (!response.ok || !result.status) {
      payment.providerError = result.message || 'Paystack checkout could not be initialized';
      saveAndSend(req, res, { reference, payment, checkoutStatus: 'failed', error: payment.providerError }, 502);
      return;
    }
    payment.authorizationUrl = result.data.authorization_url;
    payment.accessCode = result.data.access_code;
    payment.provider = 'paystack';
    saveAndSend(req, res, { reference, payment, checkoutStatus: 'initialized', authorizationUrl: result.data.authorization_url, accessCode: result.data.access_code });
  } catch (error) {
    payment.providerError = error.message;
    saveAndSend(req, res, { reference, payment, checkoutStatus: 'failed', error: 'Payment provider is temporarily unavailable' }, 502);
  }
});

app.post('/api/payment/verify', auth, (req, res) => {
  const payment = req.db.payments.find((item) => item.reference === req.body.reference || item.id === req.body.paymentId);
  if (!payment) return res.status(404).json({ error: 'Payment not found' });
  payment.status = req.body.status || 'paid';
  if (payment.status === 'paid') {
    const subscription = payment.subscriptionId ? byId(req.db.subscriptions, payment.subscriptionId) : null;
    if (subscription) subscription.status = 'active';
    if (payment.promoCode) {
      const promo = (req.db.promoCodes || []).find((item) => item.code === String(payment.promoCode).toUpperCase());
      if (promo) promo.redemptionCount = money(promo.redemptionCount) + 1;
    }
    const referral = (req.db.referrals || []).find((item) => item.referredUserId === req.user.id && item.status === 'pending_subscription');
    if (referral) referral.status = 'qualified';
  }
  audit(req.db, req.user, 'payment_verified', 'payment', payment.id, { status: payment.status });
  saveAndSend(req, res, { verified: payment.status === 'paid', payment });
});

app.post('/api/payment/webhook', (req, res) => {
  const db = readDb();
  const payment = db.payments.find((item) => item.reference === req.body.reference);
  if (payment) payment.status = req.body.status || payment.status;
  audit(db, null, 'payment_webhook_received', 'payment', payment?.id || req.body.reference || 'unknown', { provider: req.body.provider });
  writeDb(db);
  res.json({ received: true });
});

app.post('/api/questionnaire', auth, (req, res) => {
  if (!isWithin(req.body.heightCm, 90, 240)) return res.status(400).json({ error: 'Enter a valid height in centimetres' });
  if (!isWithin(req.body.weightKg, 30, 300)) return res.status(400).json({ error: 'Enter a valid weight in kilograms' });
  if (!Array.isArray(req.body.goals) || req.body.goals.length === 0) return res.status(400).json({ error: 'At least one wellness goal is required' });
  const encryptedMedicalPayload = encryptField({
    goals: req.body.goals || [],
    conditions: req.body.conditions || [],
    medications: req.body.medications || [],
    allergies: req.body.allergies || [],
  });
  const questionnaire = {
    id: id('q'),
    userId: req.user.id,
    status: 'submitted',
    heightCm: money(req.body.heightCm),
    weightKg: money(req.body.weightKg),
    bmi: req.body.heightCm ? +(money(req.body.weightKg) / ((money(req.body.heightCm) / 100) ** 2)).toFixed(1) : null,
    encryptedMedicalPayload,
    submittedAt: now(),
  };
  req.db.questionnaires.push(questionnaire);
  audit(req.db, req.user, 'questionnaire_submitted', 'questionnaire', questionnaire.id);
  saveAndSend(req, res, {
    submitted: true,
    questionnaire: { ...questionnaire, medicalPayload: decryptField(questionnaire.encryptedMedicalPayload) },
    doctorAssigned: 'Pending operations assignment',
  });
});

app.get('/api/questionnaire', auth, (req, res) => {
  const questionnaire = req.db.questionnaires.find((item) => item.userId === req.user.id);
  res.json({ completed: Boolean(questionnaire), questionnaire: questionnaireForResponse(questionnaire) });
});

app.post('/api/documents/upload', auth, (req, res) => {
  if (!String(req.body.fileName || '').trim()) return res.status(400).json({ error: 'File name is required' });
  if (!String(req.body.type || '').trim()) return res.status(400).json({ error: 'Document type is required' });
  const document = {
    id: id('cred'),
    ownerUserId: req.body.ownerUserId || req.user.id,
    ownerRole: req.body.ownerRole || req.user.role,
    type: req.body.type || 'General document',
    fileName: req.body.fileName || 'uploaded-document.pdf',
    url: req.body.url || `/uploads/${Date.now()}-${req.body.fileName || 'document.pdf'}`,
    status: 'pending',
    reviewedBy: null,
    reviewedAt: null,
    notes: '',
    uploadedAt: now(),
  };
  req.db.credentials.push(document);
  audit(req.db, req.user, 'document_uploaded', 'credential', document.id, { type: document.type });
  saveAndSend(req, res, { uploaded: true, document, url: document.url });
});

app.get('/api/documents', auth, (req, res) => {
  const canReview = ['super_admin', 'operations'].includes(req.user.role);
  const documents = canReview ? req.db.credentials : req.db.credentials.filter((doc) => doc.ownerUserId === req.user.id);
  res.json({ documents });
});

app.get('/api/progress', auth, (req, res) => {
  const logs = (req.db.progressLogs || []).filter((item) => item.userId === req.user.id).sort((a, b) => new Date(a.loggedAt) - new Date(b.loggedAt));
  res.json({
    logs,
    weights: logs.map((item) => ({ date: item.loggedAt.slice(0, 10), kg: item.weightKg })),
    bmi: logs.map((item) => ({ date: item.loggedAt.slice(0, 10), value: item.bmi })),
  });
});

app.post('/api/progress/log', auth, (req, res) => {
  if (!isWithin(req.body.weightKg, 30, 300)) return res.status(400).json({ error: 'Enter a valid weight in kilograms' });
  if (req.body.bmi && !isWithin(req.body.bmi, 10, 90)) return res.status(400).json({ error: 'Enter a valid BMI value' });
  if (req.body.waistCm && !isWithin(req.body.waistCm, 30, 250)) return res.status(400).json({ error: 'Enter a valid waist measurement' });
  const log = {
    id: id('prog'),
    userId: req.user.id,
    weightKg: money(req.body.weightKg),
    bmi: req.body.bmi ? money(req.body.bmi) : null,
    waistCm: req.body.waistCm ? money(req.body.waistCm) : null,
    notes: req.body.notes || '',
    loggedAt: now(),
  };
  req.db.progressLogs = req.db.progressLogs || [];
  req.db.progressLogs.push(log);
  audit(req.db, req.user, 'progress_logged', 'user', req.user.id, { weightKg: log.weightKg });
  saveAndSend(req, res, { logged: true, log });
});

app.get('/api/notifications', auth, (req, res) => {
  res.json({ notifications: req.db.notifications.filter((note) => note.userId === req.user.id) });
});

app.get('/api/messages', auth, (req, res) => {
  res.json({ messages: req.db.messages.filter((msg) => msg.fromUserId === req.user.id || msg.toUserId === req.user.id) });
});

app.post('/api/messages', auth, (req, res) => {
  const message = {
    id: id('msg'),
    threadId: req.body.threadId || `thread_${req.user.id}_${req.body.toUserId}`,
    fromUserId: req.user.id,
    toUserId: req.body.toUserId,
    text: req.body.text,
    secure: true,
    readAt: null,
    createdAt: now(),
  };
  req.db.messages.unshift(message);
  audit(req.db, req.user, 'secure_message_sent', 'message', message.id, { toUserId: message.toUserId });
  saveAndSend(req, res, { sent: true, message });
});

app.get('/api/admin/stats', auth, allow('super_admin', 'operations'), (req, res) => {
  res.json(summaryStats(req.db));
});

app.get('/api/admin/dashboard', auth, allow('super_admin', 'operations'), (req, res) => {
  res.json({
    stats: summaryStats(req.db),
    users: req.db.users.map(publicUser),
    subscriptions: req.db.subscriptions,
    payments: req.db.payments,
    credentials: req.db.credentials,
    consultations: req.db.consultations,
    prescriptions: req.db.prescriptions,
    orders: req.db.orders,
    payouts: req.db.payouts,
    supportTickets: req.db.supportTickets,
    auditLogs: req.db.auditLogs.slice(0, 80),
    plans: req.db.plans,
    promoCodes: req.db.promoCodes || [],
    referrals: req.db.referrals || [],
    doctorProfiles: req.db.doctorProfiles,
    pharmacyProfiles: req.db.pharmacyProfiles,
    settings: req.db.settings,
  });
});

app.get('/api/admin/promo-codes', auth, allow('super_admin', 'operations'), (req, res) => {
  res.json({ promoCodes: req.db.promoCodes || [] });
});

app.post('/api/admin/promo-codes', auth, allow('super_admin'), (req, res) => {
  req.db.promoCodes = req.db.promoCodes || [];
  const codeValue = String(req.body.code || '').trim().toUpperCase();
  if (!/^[A-Z0-9_-]{4,32}$/.test(codeValue)) return res.status(400).json({ error: 'Promo code must be 4-32 letters, numbers, dashes, or underscores' });
  if (req.db.promoCodes.some((item) => item.code === codeValue)) return res.status(409).json({ error: 'Promo code already exists' });
  const promo = {
    id: id('promo'),
    code: codeValue,
    type: req.body.type === 'fixed' ? 'fixed' : 'percent',
    value: money(req.body.value),
    description: req.body.description || '',
    appliesToPlanIds: Array.isArray(req.body.appliesToPlanIds) ? req.body.appliesToPlanIds : [],
    active: req.body.active !== false,
    maxRedemptions: req.body.maxRedemptions ? money(req.body.maxRedemptions) : null,
    redemptionCount: 0,
    startsAt: req.body.startsAt || now(),
    expiresAt: req.body.expiresAt || null,
    createdAt: now(),
  };
  if (!promo.value || promo.value < 0) return res.status(400).json({ error: 'A valid discount value is required' });
  req.db.promoCodes.unshift(promo);
  audit(req.db, req.user, 'promo_code_created', 'promo_code', promo.id, { code: promo.code });
  saveAndSend(req, res, { success: true, promo }, 201);
});

app.get('/api/admin/users', auth, allow('super_admin', 'operations'), (req, res) => {
  const role = req.query.role;
  const users = req.db.users.filter((user) => !role || user.role === role).map(publicUser);
  res.json({ users, total: users.length });
});

app.patch('/api/admin/users/:userId/status', auth, allow('super_admin', 'operations'), (req, res) => {
  const user = byId(req.db.users, req.params.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  user.status = req.body.status;
  audit(req.db, req.user, 'user_status_updated', 'user', user.id, { status: user.status });
  saveAndSend(req, res, { success: true, user: publicUser(user) });
});

app.post('/api/admin/providers/:userId/decision', auth, allow('super_admin', 'operations'), (req, res) => {
  const user = byId(req.db.users, req.params.userId);
  if (!user || !['doctor', 'pharmacy'].includes(user.role)) return res.status(404).json({ error: 'Provider not found' });
  const approved = req.body.decision === 'approve';
  user.status = approved ? 'active' : 'rejected';
  const collection = user.role === 'doctor' ? req.db.doctorProfiles : req.db.pharmacyProfiles;
  const profile = collection.find((item) => item.userId === user.id);
  if (profile) {
    profile.verificationStatus = approved ? 'approved' : 'rejected';
    profile.approvedAt = approved ? now() : null;
    profile.rejectedReason = approved ? null : req.body.reason || 'Not specified';
  }
  audit(req.db, req.user, approved ? 'provider_approved' : 'provider_rejected', user.role, user.id, { reason: req.body.reason });
  saveAndSend(req, res, { success: true, user: publicUser(user), profile });
});

app.post('/api/admin/documents/:documentId/review', auth, allow('super_admin', 'operations'), (req, res) => {
  const document = byId(req.db.credentials, req.params.documentId);
  if (!document) return res.status(404).json({ error: 'Document not found' });
  document.status = req.body.status || 'verified';
  document.reviewedBy = req.user.id;
  document.reviewedAt = now();
  document.notes = req.body.notes || '';
  audit(req.db, req.user, 'credential_reviewed', 'credential', document.id, { status: document.status });
  saveAndSend(req, res, { success: true, document });
});

app.post('/api/admin/assignments/doctor', auth, allow('super_admin', 'operations'), (req, res) => {
  const consultation = byId(req.db.consultations, req.body.consultationId);
  if (!consultation) return res.status(404).json({ error: 'Consultation not found' });
  consultation.doctorId = req.body.doctorId;
  consultation.status = 'assigned';
  const profile = req.db.doctorProfiles.find((item) => item.userId === req.body.doctorId);
  if (profile && !profile.patientsAssigned.includes(consultation.patientId)) profile.patientsAssigned.push(consultation.patientId);
  audit(req.db, req.user, 'doctor_assigned', 'consultation', consultation.id, { doctorId: req.body.doctorId });
  saveAndSend(req, res, { success: true, consultation });
});

app.post('/api/admin/assignments/pharmacy', auth, allow('super_admin', 'operations'), (req, res) => {
  const prescription = byId(req.db.prescriptions, req.body.prescriptionId);
  if (!prescription) return res.status(404).json({ error: 'Prescription not found' });
  prescription.pharmacyId = req.body.pharmacyId;
  audit(req.db, req.user, 'pharmacy_assigned', 'prescription', prescription.id, { pharmacyId: req.body.pharmacyId });
  saveAndSend(req, res, { success: true, prescription });
});

app.post('/api/admin/plans', auth, allow('super_admin'), (req, res) => {
  const plan = { id: id('plan'), status: 'active', currency: 'NGN', billingCycle: 'monthly', features: [], ...req.body };
  req.db.plans.push(plan);
  audit(req.db, req.user, 'plan_created', 'plan', plan.id);
  saveAndSend(req, res, { success: true, plan }, 201);
});

app.patch('/api/admin/plans/:planId', auth, allow('super_admin'), (req, res) => {
  const plan = byId(req.db.plans, req.params.planId);
  if (!plan) return res.status(404).json({ error: 'Plan not found' });
  Object.assign(plan, req.body);
  audit(req.db, req.user, 'plan_updated', 'plan', plan.id);
  saveAndSend(req, res, { success: true, plan });
});

app.post('/api/admin/refunds', auth, allow('super_admin', 'operations'), (req, res) => {
  const payment = byId(req.db.payments, req.body.paymentId);
  if (!payment) return res.status(404).json({ error: 'Payment not found' });
  payment.status = 'refunded';
  const ticket = {
    id: id('ticket'),
    userId: payment.userId,
    assignedTo: req.user.id,
    priority: 'medium',
    subject: `Refund processed for ${payment.reference}`,
    status: 'closed',
    messages: [req.body.reason || 'Refund processed by operations.'],
    escalated: false,
    createdAt: now(),
  };
  req.db.supportTickets.unshift(ticket);
  audit(req.db, req.user, 'refund_processed', 'payment', payment.id, { reason: req.body.reason });
  saveAndSend(req, res, { success: true, payment, ticket });
});

app.patch('/api/admin/settings', auth, allow('super_admin'), (req, res) => {
  Object.assign(req.db.settings, req.body);
  audit(req.db, req.user, 'settings_updated', 'settings', 'platform');
  saveAndSend(req, res, { success: true, settings: req.db.settings });
});

app.get('/api/admin/reports/export', auth, allow('super_admin', 'operations'), (req, res) => {
  const rows = [
    ['Metric', 'Value'],
    ['Revenue', summaryStats(req.db).revenue],
    ['Platform Commission', summaryStats(req.db).commission],
    ['Active Subscriptions', summaryStats(req.db).activeSubscriptions],
    ['Users', req.db.users.length],
    ['Pending Credentials', summaryStats(req.db).pendingCredentials],
  ];
  audit(req.db, req.user, 'report_exported', 'report', 'dashboard_csv');
  writeDb(req.db);
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="wellbodyvital-report.csv"');
  res.send(rows.map((row) => row.join(',')).join('\n'));
});

app.get('/api/doctor/dashboard', auth, allow('doctor', 'super_admin', 'operations'), (req, res) => {
  const doctorId = req.user.role === 'doctor' ? req.user.id : req.query.doctorId || 'usr_doctor';
  res.json(providerDashboard(req.db, 'doctor', doctorId));
});

app.get('/api/doctor', auth, (req, res) => {
  const doctor = req.db.users.find((user) => user.role === 'doctor');
  res.json({ name: doctor?.name || 'Doctor pending assignment', status: doctor?.status || 'pending' });
});

app.get('/api/doctor/messages', auth, (req, res) => {
  res.json({ messages: req.db.messages.filter((msg) => msg.fromUserId === req.user.id || msg.toUserId === req.user.id) });
});

app.post('/api/doctor/message', auth, allow('doctor', 'patient'), (req, res) => {
  const message = {
    id: id('msg'),
    threadId: req.body.threadId || `thread_${req.user.id}_${req.body.toUserId}`,
    fromUserId: req.user.id,
    toUserId: req.body.toUserId,
    text: req.body.text,
    secure: true,
    readAt: null,
    createdAt: now(),
  };
  req.db.messages.unshift(message);
  audit(req.db, req.user, 'secure_message_sent', 'message', message.id);
  saveAndSend(req, res, { sent: true, message });
});

app.post('/api/doctor/book', auth, (req, res) => {
  const consultation = {
    id: id('consult'),
    patientId: req.user.id,
    doctorId: req.body.doctorId || 'usr_doctor',
    questionnaireId: req.body.questionnaireId || null,
    status: 'scheduled',
    eligibility: 'pending',
    recommendation: '',
    followUpAt: req.body.date || new Date(Date.now() + 3 * 86400000).toISOString(),
    sideEffects: [],
    createdAt: now(),
  };
  req.db.consultations.push(consultation);
  audit(req.db, req.user, 'consultation_booked', 'consultation', consultation.id);
  saveAndSend(req, res, { booked: true, consultation, date: consultation.followUpAt });
});

app.post('/api/doctor/consultations/:consultationId/decision', auth, allow('doctor'), (req, res) => {
  const consultation = byId(req.db.consultations, req.params.consultationId);
  if (!consultation || consultation.doctorId !== req.user.id) return res.status(404).json({ error: 'Consultation not found' });
  consultation.eligibility = req.body.eligibility || 'approved';
  consultation.status = consultation.eligibility === 'approved' ? 'approved' : 'rejected';
  consultation.recommendation = req.body.recommendation || consultation.recommendation;
  consultation.followUpAt = req.body.followUpAt || consultation.followUpAt;
  audit(req.db, req.user, 'medical_decision_recorded', 'consultation', consultation.id, { eligibility: consultation.eligibility });
  saveAndSend(req, res, { success: true, consultation });
});

app.post('/api/doctor/prescriptions', auth, allow('doctor'), (req, res) => {
  const prescription = {
    id: id('rx'),
    patientId: req.body.patientId,
    doctorId: req.user.id,
    pharmacyId: req.body.pharmacyId || null,
    consultationId: req.body.consultationId,
    medication: req.body.medication,
    dosage: req.body.dosage,
    status: 'approved',
    auditTrail: [{ at: now(), by: req.user.id, action: 'prescription_issued' }],
    issuedAt: now(),
  };
  req.db.prescriptions.push(prescription);
  audit(req.db, req.user, 'prescription_issued', 'prescription', prescription.id, { patientId: prescription.patientId });
  saveAndSend(req, res, { success: true, prescription }, 201);
});

app.post('/api/doctor/side-effects', auth, allow('doctor', 'patient'), (req, res) => {
  const consultation = byId(req.db.consultations, req.body.consultationId);
  if (!consultation) return res.status(404).json({ error: 'Consultation not found' });
  const report = { at: now(), by: req.user.id, severity: req.body.severity || 'medium', notes: req.body.notes || '' };
  consultation.sideEffects.push(report);
  audit(req.db, req.user, 'side_effect_reported', 'consultation', consultation.id, { severity: report.severity });
  saveAndSend(req, res, { success: true, report });
});

app.get('/api/pharmacy/dashboard', auth, allow('pharmacy', 'super_admin', 'operations'), (req, res) => {
  const pharmacyId = req.user.role === 'pharmacy' ? req.user.id : req.query.pharmacyId || 'usr_pharmacy';
  res.json(providerDashboard(req.db, 'pharmacy', pharmacyId));
});

app.get('/api/pharmacy/orders', auth, (req, res) => {
  let orders = [];
  if (req.user.role === 'patient') {
    orders = req.db.orders.filter((order) => order.patientId === req.user.id);
  } else if (req.user.role === 'pharmacy') {
    orders = req.db.orders.filter((order) => order.pharmacyId === req.user.id);
  } else if (['operations', 'super_admin'].includes(req.user.role)) {
    const pharmacyId = req.query.pharmacyId;
    orders = req.db.orders.filter((order) => !pharmacyId || order.pharmacyId === pharmacyId);
  }
  res.json({ orders });
});

app.patch('/api/pharmacy/orders/:orderId/status', auth, allow('pharmacy', 'operations', 'super_admin'), (req, res) => {
  const order = byId(req.db.orders, req.params.orderId);
  if (!order) return res.status(404).json({ error: 'Order not found' });
  if (req.user.role === 'pharmacy' && order.pharmacyId !== req.user.id) return res.status(403).json({ error: 'Order belongs to another pharmacy' });
  order.status = req.body.status || order.status;
  order.coldChainConfirmed = req.body.coldChainConfirmed ?? order.coldChainConfirmed;
  order.proofOfFulfillmentUrl = req.body.proofOfFulfillmentUrl ?? order.proofOfFulfillmentUrl;
  order.updatedAt = now();
  audit(req.db, req.user, 'order_status_updated', 'order', order.id, { status: order.status });
  saveAndSend(req, res, { success: true, order });
});

app.post('/api/pharmacy/inventory', auth, allow('pharmacy'), (req, res) => {
  const item = {
    id: id('inv'),
    pharmacyId: req.user.id,
    medication: req.body.medication,
    quantity: money(req.body.quantity),
    coldChain: Boolean(req.body.coldChain),
    nafdacDocStatus: req.body.nafdacDocStatus || 'pending',
    updatedAt: now(),
  };
  req.db.inventory.push(item);
  audit(req.db, req.user, 'inventory_added', 'inventory', item.id);
  saveAndSend(req, res, { success: true, item }, 201);
});

app.patch('/api/pharmacy/inventory/:inventoryId', auth, allow('pharmacy'), (req, res) => {
  const item = byId(req.db.inventory, req.params.inventoryId);
  if (!item || item.pharmacyId !== req.user.id) return res.status(404).json({ error: 'Inventory item not found' });
  Object.assign(item, req.body, { updatedAt: now() });
  audit(req.db, req.user, 'inventory_updated', 'inventory', item.id);
  saveAndSend(req, res, { success: true, item });
});

app.post('/api/pharmacy/refill', auth, (req, res) => {
  audit(req.db, req.user, 'refill_requested', 'prescription', req.body.prescriptionId || 'unknown');
  saveAndSend(req, res, { requested: true });
});

app.post('/api/pharmacy/report', auth, (req, res) => {
  audit(req.db, req.user, 'pharmacy_issue_reported', 'order', req.body.orderId || 'unknown', { notes: req.body.notes });
  saveAndSend(req, res, { reported: true });
});

app.get('*', (req, res) => {
  res.sendFile(path.join(APP_ROOT, 'public', 'index.html'));
});

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`WellBodyVital running at http://localhost:${PORT}`);
    console.log(`Back office available at http://localhost:${PORT}/admin`);
  });
}

module.exports = app;
