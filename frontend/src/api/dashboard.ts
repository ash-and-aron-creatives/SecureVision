import type { ApiRequester } from "./types";
import { fetchAuditLog } from "./audit";
import { fetchUsers } from "./users";
import type { Asset, AuditEntry, DashboardAnalytics, Finding, FindingsPage, UserItem, UserRole } from "../types";

const FINDINGS_PAGE_SIZE = 100;
const MAX_FINDINGS = 10_000;

async function fetchAllFindings(apiRequest: ApiRequester, authToken: string) {
  const firstPage = await apiRequest<FindingsPage>(
    `/findings?page=1&page_size=${FINDINGS_PAGE_SIZE}`,
    authToken,
  );
  const findings: Finding[] = firstPage.items.slice(0, MAX_FINDINGS);
  const pagesToFetch = Math.min(firstPage.pages, Math.ceil(MAX_FINDINGS / FINDINGS_PAGE_SIZE));

  for (let page = 2; page <= pagesToFetch && findings.length < MAX_FINDINGS; page += 1) {
    const response = await apiRequest<FindingsPage>(
      `/findings?page=${page}&page_size=${FINDINGS_PAGE_SIZE}`,
      authToken,
    );
    findings.push(...response.items.slice(0, MAX_FINDINGS - findings.length));
  }

  return {
    findings,
    findingsTotal: firstPage.total,
    findingsTruncated: firstPage.total > findings.length,
  };
}

export async function fetchDashboardData(
  apiRequest: ApiRequester,
  authToken: string,
  role: UserRole | "",
) {
  const [findingsResponse, assetsResponse, analytics] = await Promise.all([
    fetchAllFindings(apiRequest, authToken),
    apiRequest<Asset[]>("/assets", authToken),
    apiRequest<DashboardAnalytics>("/dashboard/analytics", authToken),
  ]);
  let auditLogs: AuditEntry[] = [];
  let users: UserItem[] = [];
  if (role === "admin") {
    [auditLogs, users] = await Promise.all([
      fetchAuditLog(apiRequest, authToken),
      fetchUsers(apiRequest, authToken),
    ]);
  }
  return {
    ...findingsResponse,
    assets: assetsResponse,
    analytics,
    auditLogs,
    users,
  };
}
