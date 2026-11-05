# UI Styling Guide

## Current structure

- `frontend/src/app/layout.tsx` is the App Router root layout. It imports `globals.css` and renders the page in the document body.
- `frontend/src/app/page.tsx` is a client component. It owns the splash-to-landing flow, the marketing navigation and sections, and the transition into the product app.
- `frontend/src/app/SecureApp.tsx` contains the authenticated product experience and its stateful views. The application is implemented in this file rather than split into per-view components.
- `frontend/src/app/globals.css` contains Tailwind directives, the page background and text colors, and global scrollbar styles.
- `frontend/tailwind.config.ts` defines the `secure` color tokens and shared animation keyframes.

## Styling approach

Most UI styling is expressed with Tailwind utility classes in JSX. Reuse the configured `secure` palette (`bg`, `surface`, `border`, `text`, `accent`, `neon`, and `lavender`) where it fits, and use responsive utilities for layout changes. The marketing splash in `page.tsx` has its own inline keyframes; keep those animation-specific styles scoped there rather than adding unrelated global rules.

`SecureApp.tsx` supports a stored light/dark theme preference (`sv_theme`) and uses responsive navigation. Follow its existing theme and navigation patterns when styling authenticated views; do not assume every screen is dark-only or desktop-only.

## Screens and styling surfaces

### Public landing flow (`page.tsx`)

- Animated splash state, followed by the marketing landing page.
- Header navigation with dropdowns, search and mobile navigation state.
- Platform, Solutions, Resources, and Company sections.
- Calls to action switch to the product application.

### Product application (`SecureApp.tsx`)

- Login form and authentication feedback.
- Responsive application navigation and theme control.
- Dashboard and finding Queue.
- Manual Scan, CSV Import, and Assets views.
- Admin-only Audit and Users views.
- Finding detail/explanation overlay and command palette.

The visible user-management and audit views are role-gated in the UI. Keep those conditions and the corresponding API interactions intact when changing presentation.

## Safe styling changes

- Prefer changes to the relevant JSX `className` values and existing Tailwind tokens over introducing new global selectors.
- Keep state, API requests, payload shapes, imports, and role checks unchanged for presentation-only work.
- Preserve the current splash animation scope, responsive navigation behavior, theme persistence, finding explanation, CSV preview/commit flow, and existing export actions.
- Update this guide when the page/component structure, styling system, or user-facing views change.
