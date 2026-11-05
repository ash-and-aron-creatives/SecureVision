import type { IntelResponse } from "../types";
import type { ApiRequester } from "./types";

export function lookupIntel(
  apiRequest: ApiRequester,
  authToken: string,
  cveId: string,
): Promise<IntelResponse> {
  return apiRequest<IntelResponse>(`/intel/${encodeURIComponent(cveId)}`, authToken);
}
