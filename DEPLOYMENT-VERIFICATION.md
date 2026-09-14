# Vajrion Deployment Verification

Validation date: 2026-09-14

## What was validated

### Backend runtime
- All modified Node.js backend files passed `node --check`.
- PostgreSQL production adapter was reviewed for pooled connections, transactions, parameterized placeholders, identity columns, `BYTEA` evidence storage and automatic schema initialization.
- Production startup explicitly fails when a PostgreSQL connection URL or JWT secret is missing under Vercel/production.

### API acceptance suite
The full smoke suite was run against an isolated copy of the uploaded application database using a Node 22 SQLite compatibility harness that exercises the same application-facing `db.prepare().get/all/run()` and transaction contract used by the PostgreSQL adapter.

**Result: 90/90 checks passed.**

Coverage included:
- health check
- signup/login/me/password change
- dashboard and FIR listing for all roles
- police-station lookup
- Admin officer creation and verify/unverify flow
- FIR creation and automatic FIR copy
- case access and RBAC restrictions
- IO assignment and case progress updates
- case timeline, important dates, lawyers and court proceedings
- evidence upload, metadata retrieval, binary content download, SHA-256 verification and redaction
- notifications and read state
- completion request, citizen approval and citizen rejection
- Admin audit listing and audit-chain verification
- role-denied audit access

### Evidence security
AES-256-GCM encryption/decryption and tamper rejection passed the backend encryption test.

### Frontend source validation
The React entrypoints `frontend/src/App.jsx` and `frontend/src/main.jsx` were parsed successfully as JSX modules.

The uploaded `node_modules` directory was **not** used as a production dependency source and is excluded from the final ZIP. It contains Windows-native optional Rollup binaries; this prevented a local Vite dev/build run in the current Linux execution environment. A fresh `npm install` on Vercel will resolve the correct Linux optional packages from the dependency manifests.

### PostgreSQL live-test limitation
No PostgreSQL server or valid hosted PostgreSQL credentials were available in the execution environment, so a live database integration test against PostgreSQL could not be performed here. The production code path is isolated behind the PostgreSQL adapter and the API acceptance suite passed against the compatibility harness. The deployment procedure therefore includes a required post-deploy `/api/health` check and application smoke test.

## Important packaging decisions

- No SQLite production database is included.
- No `.env` or secret is included.
- No `node_modules` is included.
- `better-sqlite3` is removed from production dependencies.
- Evidence responses no longer embed base64 content in JSON; binary evidence is returned through `/api/documents/:id/content` so normal responses stay below Vercel response limits.
- Evidence upload defaults to 3.5 MB, below Vercel's documented 4.5 MB function request payload limit.
