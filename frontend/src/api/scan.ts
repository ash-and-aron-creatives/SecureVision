import type { ScanResult } from "../types";
import type { ApiRequester } from "./types";

export function createScan(
  apiRequest: ApiRequester,
  authToken: string,
  payload: {
    asset_id: number;
    cve_id: string;
    cvss_score: number | null;
    in_kev: boolean;
    epss_percentile: number | null;
  },
): Promise<ScanResult> {
  return apiRequest<ScanResult>("/scan", authToken, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}
