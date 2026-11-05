import type { ApiRequester } from "./types";
import { fetchAuditLog } from "./audit";
import { fetchUsers } from "./users";
import type { Asset, AuditEntry, DashboardAnalytics, FindingsPage, UserItem, UserRole } from "../types";

export async function fetchDashboardData(
  apiRequest: ApiRequester,
  authToken: string,
  role: UserRole | "",
) {
  const [findingsResponse, assetsResponse, analytics] = await Promise.all([
    apiRequest<FindingsPage>("/findings", authToken),
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
  return { findings: findingsResponse.items, assets: assetsResponse, analytics, auditLogs, users };
}
