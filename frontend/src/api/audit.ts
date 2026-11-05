import type { AuditEntry } from "../types";
import type { ApiRequester } from "./types";

export function fetchAuditLog(apiRequest: ApiRequester, authToken: string): Promise<AuditEntry[]> {
  return apiRequest<AuditEntry[]>("/audit", authToken);
}
