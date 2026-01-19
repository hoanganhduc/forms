# form-app

Monorepo for a Cloudflare Worker API (apps/api) and a Vite + React web app (apps/web).
The app supports public forms, OAuth (Google/GitHub), user submissions, file uploads
with VirusTotal scanning, and optional Google Drive finalization.

This codebase was developed with the assistance of GitHub Copilot, ChatGPT Codex, and Google Antigravity.

## Prereqs
- Node.js (npm)

## Setup
- `npm install`

## Local dev
- `npm run dev` (runs API + web)
- `npm run dev:api`
- `npm run dev:web`
- For web env overrides:
  - `VITE_API_BASE=http://127.0.0.1:8787 VITE_WEB_BASE=/forms/ npm run dev:web`
- Open `http://localhost:5173/forms/` for the homepage and public form list.
- Login buttons redirect to OAuth and return to the app after authentication.
- Admin UI (after login): `http://localhost:5173/forms/#/admin`
- Builder UI (admin): `http://localhost:5173/forms/#/admin/builder` (create/edit forms & templates)
- Admin nav entries (under Admin tab): Admin Dashboard, Builder, Canvas, Emails, Trash.
- Public fill route: `http://localhost:5173/forms/#/f/hus-demo-1`
- Docs: `http://localhost:5173/forms/#/docs`
- File upload test: choose a file on the form page and submit; API stores in R2.
- Form runtime test:
  - Open `http://localhost:5173/forms/#/f/hus-demo-1`
  - Verify fields render, submit, and resubmit if unlocked.
- File upload test:
  - Submit the form to create a submission ID.
  - Select files in a file field and click "Upload selected files".
  - Use "Check status" to poll VirusTotal and finalize to Drive when clean.
- Dashboard test:
  - Sign in and open `http://localhost:5173/forms/#/me`
  - Verify the form appears after at least one submission.
- Clean local caches (keeps env files): `clean.bat`
- Theme: dark is default; the toggle persists in localStorage.
- Theme toggle: floating button at bottom-right.
- Form drafts: unsent inputs auto-save to localStorage and can be restored on return.
- Import/export: download Markdown or JSON, and import either format to fill a form (auto-detected).
- Builder: duplicate forms/templates to speed up reuse.
- Rich text: Markdown + MathJax rendering can be toggled in Admin App settings (raw HTML stripped).

## Mobile QA
- Run `npm run dev:web` and open `http://localhost:5173/forms/`.
- Use device emulation:
  - iPhone SE (375x667)
  - iPhone 14 Pro (393x852)
  - Pixel 7 (412x915)
  - iPad Mini (768x1024)
- Verify:
  - No horizontal scrolling.
  - Mobile menu drawer opens/closes and links work.
  - Login buttons are full-width and tappable.
  - Form fill fields stack vertically and errors are readable.
  - Sticky submit bar appears and does not cover content.
  - Admin lists remain readable on mobile.

## Migrations
- `npm run migrate:local -w apps/api`
- `npm run migrate:remote -w apps/api`

## Smoke test
- `API_BASE=http://127.0.0.1:8787 TOKEN=your_jwt npm run smoke:api`
- `API_BASE=http://127.0.0.1:8787 TOKEN=your_jwt npm run smoke:canvas`

## Admin exports
- CSV: `GET /api/admin/forms/:slug/export.csv`
- TXT (JSONL): `GET /api/admin/forms/:slug/export.txt`
- Optional field filter: add `fields=full_name,email` to export only specific data keys (CSV/TXT).

## Routine tasks + health
- Admin dashboard shows routine tasks (cron-based) and health status history.
- Routine tasks support bulk run/save and enable/disable actions; latest run time appears in status.
- Admin listings support bulk select + move-to-trash for forms/templates/users/submissions.
- Built-in tasks:
  - Canvas sync (courses + sections)
  - Canvas name mismatch checker
  - Canvas retry queue processor
  - Backup forms + templates (R2 + Drive `/backups`)
  - Empty trash
  - Test notice
- Routine run logs are retained (last 100 per task, last 30 days).
- Admin Canvas page shows retry queue + dead letters with Retry/Drop actions.
- Health endpoints:
  - `GET /api/admin/health/summary`
  - `GET /api/admin/health/history?service=...&limit=...`

## Canvas enrollment
- Configure Canvas vars (API):
  - `CANVAS_API_TOKEN` (secret)
  - `CANVAS_BASE_URL` (default `https://canvas.instructure.com`)
  - `CANVAS_ACCOUNT_ID` (optional fallback if `accounts/self` is unavailable)
- Admin workflow:
  - Go to Builder, enable Canvas enrollment for a form.
  - Sync courses + sections and select the course/sections.
  - Ensure the form includes **Full Name** and **Email** fields.
- Submission flow:
  - User submits the form; API enrolls them and stores status in the submission.

## Deploy: GitHub Pages (web)
- Build:
  - `VITE_API_BASE=https://form-app-api.hoanganhduc.workers.dev VITE_WEB_BASE=/forms/ npm run build:web`
- Upload `apps/web/dist` to GitHub Pages (via your pages.yml workflow).
- Access at `https://hoanganhduc.github.io/forms/`.

## Deploy: Cloudflare Workers (api)
- Ensure `apps/api/wrangler.toml` has correct bindings:
  - D1, KV, R2, and vars (`BASE_URL_API`, `BASE_URL_WEB`, `ALLOWED_ORIGIN`, etc).
- Run migrations:
  - `npx wrangler d1 migrations apply form_app_db --remote`
- Deploy:
  - `cd apps/api && npx wrangler deploy -c wrangler.toml`

## Quick API reference
- `GET /api/health`
- `GET /api/forms`
- `GET /api/forms/:slug`
- `POST /api/submissions`
- `GET /api/me`
- `GET /api/me/identities`
- `GET /api/me/submissions`
- `GET /api/me/submissions/:id`
- `GET /api/me/submission?formSlug=...`
- `GET /api/admin/canvas/courses`
- `GET /api/admin/canvas/courses/:id/sections`
- `POST /api/admin/canvas/sync`
- `GET /api/admin/canvas/retry-queue`
- `POST /api/admin/canvas/retry-queue/:id/retry`
- `POST /api/admin/canvas/retry-queue/:id/drop`
- `GET /api/admin/health/summary`
- `GET /api/admin/health/history`
- `GET /api/admin/routines`
- `POST /api/admin/routines`
- `POST /api/admin/routines/run`
- `GET /api/admin/emails/presets`
- `POST /api/uploads/init`
- `PUT /api/uploads/put`
- `POST /api/uploads/complete`
- `GET /api/submissions/upload/status`

## App routes
- Public:
  - `/#/` home + public forms
  - `/#/f/:slug` form fill
  - `/#/docs` docs
- User:
  - `/#/me` dashboard
  - `/#/me/submissions/:id` submission detail
  - `/#/account` linked identities + delete account
  - `/#/canvas` user Canvas info (visible after Canvas-related submission)
- Admin:
  - `/#/admin` dashboard

## OAuth + account linking
- Login:
  - `GET /auth/login/google`
  - `GET /auth/login/github`
- Link providers (must be signed in):
  - `GET /auth/link/google`
  - `GET /auth/link/github`
- Deleted users cannot re-login; OAuth callback redirects to `/account?error=user_deleted`.

## Upload flow (current)
The API uses a staged upload flow:
1) `POST /api/uploads/init` to create draft upload metadata.
2) `PUT /api/uploads/put` to upload bytes to R2.
3) `POST /api/uploads/complete` to create a DB row and kick off VirusTotal.
4) `POST /api/uploads/vt/recheck` (admin) or per-file "Check status" to update VT status.
5) Finalization happens when scans are clean and Drive is configured.

## Backups
- Admin can export selected forms/templates into JSON backups.
- Backup routine task stores JSON in R2 and Google Drive:
  - R2: `backups/forms-<timestamp>.json`, `backups/templates-<timestamp>.json`
  - Drive: `<drive root>/backups/forms/` and `<drive root>/backups/templates/`
- Restore flow handles slug conflicts:
  - If a matching slug is in trash, you can restore it instead of overwriting.

## Template visibility
- Template visibility is deprecated. The `templates.is_public` column remains for compatibility,
  but the API and UI ignore it and treat all templates as reusable.

## Field rules
- Email fields can require a specific domain (e.g., `example.com`). Server-side validation enforces it.
- Email fields can auto-fill from the logged-in user when enabled in the builder. If the login
  email domain does not match the required domain, the user can still manually enter a valid
  email address for that domain.
- GitHub Username fields can auto-fill from the logged-in GitHub identity and are validated server-side.
- When GitHub auto-fill is disabled, the UI checks the username exists on GitHub (blur) and the API enforces it.
- Full Name fields normalize to title-case on submit (e.g., `john wick` -> `John Wick`).
- URL fields accept only valid `http`/`https` links and auto-prefix missing schemes on blur/submit.
- Date/Time fields let you choose date only, time only, or both; submissions store UTC plus the chosen timezone key.
- Form availability uses a timezone selector; open/close times are stored in UTC.
- The timezone picker is searchable and uses the full IANA list with a curated fallback (Asia/Ho_Chi_Minh always available).
- Admin can set a global default timezone (Admin App settings); times are displayed in the viewer's local timezone.
- Markdown/MathJax rendering is global (Admin App settings) and applies to form titles, descriptions, labels, and text values. Raw HTML is stripped.

## Deletion policy
- User deletes account via `DELETE /api/me`:
  - Soft-deletes the user and all related submissions/files.
  - Clears auth cookie immediately.
  - Login is blocked for deleted users until an admin restores the account.
- Admin App settings: �Canvas sync on delete/restore� toggles whether delete/restore
  actions deactivate/reactivate Canvas enrollments, and whether hard delete actions
  unenroll Canvas users.
- Admin can restore or permanently delete users via the trash tools.
- Soft-deleted items are visible in the Trash tab; admin can restore or purge.

## Builder workflow (admin)
- Use the Builder tab to create or edit forms/templates.
- Toggle **New** vs **Edit**:
  - **New**: enter slug/title/template and status fields, then create.
  - **Edit**: select an existing item and update schema/settings.
- Edit form: optionally select a template; “Refresh from template” appears only when selected.
- Field builder supports: text, textarea, number, date/time, email, URL, GitHub username, full name,
  select, checkbox, and file fields.
- File fields: configure extensions, max size, and max files; rules are stored per field.
- Use drag handles to reorder fields; ordering is saved in schema JSON.

## Admin submissions access
- Admin can open any submission detail at `/#/me/submissions/:id`.
- Recent submissions list links each submission ID to that detail view.

## Emails
- Admin Emails page shows sent email logs and supports move-to-trash + restore.
- Test send uses predefined templates from `GET /api/admin/emails/presets` plus a custom option.

## Secrets checklist
- Never commit `.env`, `.env.local`, or `.dev.vars` files with real secrets.
- Keep OAuth client secrets, JWT secrets, and Cloudflare tokens in GitHub Secrets or local env files.
- Verify example files (`.env.example`, `apps/api/.dev.vars.example`) contain no real credentials.

## Web env vars
- `VITE_API_BASE` (optional): API base URL override.
- `VITE_WEB_BASE` (optional): Base path for GitHub Pages (default `/forms/`).

## API env vars (uploads + Drive)
- `VT_API_KEY` (optional): VirusTotal API key for scanning.
- `VT_STRICT` (optional): `true` to block finalization when scans are pending or malicious.
- `DRIVE_SERVICE_ACCOUNT_JSON`: Service account JSON (shared drive access required).
- `DRIVE_PARENT_FOLDER_ID`: Shared drive folder ID where form folders are created.
- `CANVAS_BASE_URL`: Canvas base URL (default `https://canvas.instructure.com`).
- `CANVAS_API_TOKEN`: Canvas admin token (secret).
- `CANVAS_ACCOUNT_ID` (optional): fallback account for user creation.

## Drive setup notes
- Ensure the service account has access to the shared drive (add it as a member).
- Use the shared drive folder ID (starts with `0A`) for `DRIVE_PARENT_FOLDER_ID`.
- The API creates folders as `<root>/<formSlug>/<username>` for finalized uploads.

## Build
- `npm run build:web`

## Environment
- Copy `.env.example` to `.env` for web app config.
- Copy `apps/api/.dev.vars.example` to `apps/api/.dev.vars` for Wrangler local vars.
- Copy `apps/web/.env.example` to `apps/web/.env.local` for web app overrides.
