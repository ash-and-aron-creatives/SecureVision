# UI Styling Guide

## Current structure

The frontend is organized under `frontend/src` by responsibility:

- `app/` contains the Next.js App Router entry points. `page.tsx` implements the public landing page and `SecureApp.tsx` wires the authenticated application together.
- `api/` contains the shared API client and typed endpoint functions, including login, scans, and CVE intelligence.
- `components/` contains the page and feature views (login, dashboard, findings, scan, import, assets, audit, and users).
- `hooks/` contains feature state and workflows such as login, scanning, CSV import, and dashboard data.
- `types/` contains shared API and view contracts.
- `app/globals.css` contains global styles; `frontend/tailwind.config.ts` defines the shared Tailwind theme and animations.

`SecureApp.tsx` composes the hooks and passes data and handlers to feature components. Keep presentation changes in the relevant component rather than growing the app shell into a collection of screen implementations.

## Styling approach

Most styling uses Tailwind utility classes in component JSX. Follow nearby components for palette, spacing, borders, and responsive breakpoints. The existing UI supports dark and light themes, responsive navigation, and role-gated administrator views; retain these behaviors when styling a feature.

Use global CSS only for genuinely global behavior. Keep page-specific animation and layout styling scoped to the page or component that owns it.

## Feature surfaces

- Public landing and marketing content: `app/page.tsx`.
- Authentication and application composition: `app/SecureApp.tsx` and `components/login/`.
- Dashboard and queue: `components/dashboard/` and `components/findings/`.
- Manual scoring and CVE intelligence lookup: `components/scan/`, backed by `hooks/useScan.ts` and `api/intel.ts`.
- CSV preview/commit, assets, audit, and user management: their matching feature folders under `components/`, with corresponding hooks and API modules.

## Safe styling changes

- Prefer local JSX classes and existing Tailwind configuration over unrelated global selectors.
- For presentation-only changes, leave API payloads, state workflows, and role checks intact.
- Preserve theme persistence, responsive navigation, CVE intelligence availability messaging, finding explanations, CSV preview/commit behavior, and export actions.
- Update this guide when the source structure or user-facing feature surfaces change.
