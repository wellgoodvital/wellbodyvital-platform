# WellBodyVital Backend Data Model

The current prototype persists to `data/wbv-db.json` so it can run locally without external services. These collections are intentionally shaped as future database tables.

## Core Identity

- `users`: all patients, super admins, operations staff, doctors, and pharmacies.
- `doctorProfiles`: MDCN number, specialty, active practice status, verification state, consultation rate, assigned patients.
- `pharmacyProfiles`: PCN details, premises license, cold-chain capability, coverage states, verification state.
- `credentials`: uploaded licenses, IDs, CVs, business registrations, NAFDAC documents, review notes, reviewer, review status.
- `consentRecords`: medical data consent, telehealth consent, terms, privacy versions, acceptance timestamps.

## Subscription And Payments

- `plans`: Starter, Pro, Premium pricing, fees, commission rates, feature list, status.
- `subscriptions`: patient plan enrollment, billing status, start date, next billing date, renewal count.
- `payments`: subscription, consultation, fulfillment, refund status, channel, reference, commission, doctor fee, pharmacy fee.
- `payouts`: doctor and pharmacy payout recipient, amount, source payments, status, due date, paid date.

## Care Delivery

- `questionnaires`: medical intake, BMI, goals, conditions, medications, allergies, submission status.
- `consultations`: patient, doctor, questionnaire, eligibility decision, recommendation, follow-up, side-effect reports.
- `prescriptions`: patient, doctor, pharmacy, medication, dosage, status, issue date, prescription audit trail.
- `messages`: secure chat thread, sender, recipient, text, read timestamp, created timestamp.

## Pharmacy Fulfillment

- `orders`: prescription, patient, pharmacy, fulfillment status, cold-chain flags, address, proof of fulfillment.
- `deliveries`: order, courier, tracking code, delivery status, failure reason.
- `inventory`: pharmacy stock, quantity, cold-chain requirement, NAFDAC document status.

## Operations And Compliance

- `notifications`: user notification feed.
- `supportTickets`: ticket subject, priority, status, assignment, escalation, messages.
- `auditLogs`: actor, role, action, entity type, entity ID, details, timestamp, IP.
- `settings`: country, currency, NDPR retention, assignment controls, payout day, support email.

Sensitive workflows in the API write to `auditLogs`, including login, document upload/review, provider approval, medical decisions, prescriptions, order changes, refunds, report exports, and settings updates.
