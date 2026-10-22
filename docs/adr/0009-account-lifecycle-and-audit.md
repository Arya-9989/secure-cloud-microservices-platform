# 0009. Account lifecycle and an audit trail

- Status: accepted
- Date: 2026-10-23

## Context

A review of what production users and operators would expect found four gaps in auth-service:

1. A user can't change their password, and so can't sign out a lost device.
2. A user can't delete their account (a GDPR erasure request needs an administrator, who could only disable it).
3. Administrators can page through users but can't find one.
4. Security-relevant changes (role changes, disabled accounts, new service clients) exist only as log lines, which can't be queried, filtered or kept apart from operational logs.

## Decision

- **`POST /api/v1/auth/password/`** needs the current password. The new one goes through the same validators as registration and must differ. Every refresh token is revoked (`PASSWORD_CHANGED`), the current device included, so a stolen session ends with the change. Access tokens already issued expire within 15 minutes, as with any revocation in this design (offline verification).
- **`DELETE /api/v1/auth/me/`** needs the password and deletes the user, whose refresh tokens cascade. The last active administrator can't delete themselves: the check locks the other admin rows, so two admins can't race each other into a platform with none. Orders stay with orders-service under the account's opaque id, which no longer maps to a person. Order records are business records with their own retention rules, and they carry no personal data beyond that id.
- **Both are throttled per account** (`ACCOUNT_CHANGE_RATE_PER_ACCOUNT`, 10 per hour), which bounds password guessing by someone holding a stolen access token. Reading `/me/` isn't throttled.
- **Admin user search:** `email` (case-insensitive substring), `role` and `is_active` on the existing paginated list. Invalid values get a `400`, never an empty result that looks valid.
- **`AuditEvent`:** an append-only table holding the action, actor id, target, source IP (honouring the trusted-proxy count), request id and non-sensitive details (role from/to, sessions revoked, client scopes). It never holds emails, passwords, tokens or secrets, so the trail survives an account's erasure without keeping personal data. It's written in the same transaction as the change it records, so an event can't exist for a change that rolled back, and vice versa. Events are recorded for admin role and status changes (no-op updates are skipped), password changes, account deletions, and service-client provisioning (only when something changed, although `auth-init` runs on every start).
- **`GET /api/v1/admin/audit-events/`** (`users:admin`) is paginated and filterable by `action` and `target_id`. Nothing in the API updates or deletes events.

## Consequences

- Every sensitive change answers "who, what, when, from where", and correlates with logs and traces through the request id.
- The table grows without bound. Partitioning, retention and shipping to a SIEM are left to the operator; the structured `audit` log line makes shipping easy.
- Password reset by email isn't part of this: it needs an outbound mail channel, which this platform doesn't have.
