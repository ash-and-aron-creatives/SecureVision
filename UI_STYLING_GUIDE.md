# SecureVision ? UI/UX Styling Handoff Guide

## 1. Frozen Architecture Rules (Do Not Modify)
- **Primary File:** `frontend/src/app/page.tsx` and `frontend/src/app/globals.css`
- **API Contracts & State Hooks:** All `useState`, `useEffect`, and `axios` calls to `http://127.0.0.1:8000` are frozen and verified against 29 automated backend tests. Do not rename state variables or alter payload keys.
- **Role-Based Access Guards (RBAC):** Keep all `{role === "admin" && ...}` and `{role !== "viewer" && ...}` conditional rendering blocks intact.
- **CSV Formula-Injection & Blob Downloads:** Keep `handleExportCsv`, `handleExportPdf`, and the 2-step CSV Import preview/commit handlers untouched.

## 2. Views Available to Style
1. **Authentication Screen (`!token`):** Login card, brand header, error alert badge.
2. **Sidebar Navigation:** 6 view switches (`dashboard`, `scan`, `import`, `assets`, `audit`, `users`) + Logout footer.
3. **Dashboard View (`view === "dashboard"`):**
   - 4 KPI Summary Cards (`Total Findings`, `P1 - Critical`, `P2 - High`, `P3/P4 - Medium & Low`)
   - Severity Distribution Chart (`Recharts` BarChart)
   - Multi-Filter Bar (Search input, Priority, Status, Asset filter, Sort selector, Export CSV & Export PDF buttons)
   - Prioritized Vulnerability Queue Table + Status Select Dropdown + `Explain` Provenance Button
4. **320-Rule Provenance Modal (`selectedFinding`):** Glassmorphic overlay displaying rule ID, input vector (`KEV`, `Exposure`, `Criticality`, `EPSS`, `CVSS`), and human-readable explanation.
5. **Manual Scan (`view === "scan"`):** Asset selector, CVE input, CVSS/EPSS sliders, KEV toggle.
6. **Batch CSV Import (`view === "import"`):** Drag/drop file input, Preview summary badges, Error table, Commit button.
7. **Assets Registry (`view === "assets"`):** Asset creation form & inventory table.
8. **Immutable Audit Trail (`view === "audit"`):** Chronological security event log table with SHA-256 export hashes.
9. **Users RBAC Management (`view === "users"`):** Admin user creation form, role selector (`admin`, `analyst`, `viewer`), and delete action.
