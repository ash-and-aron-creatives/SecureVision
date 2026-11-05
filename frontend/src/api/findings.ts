import type { StatusUpdate } from "../types";
import type { ApiRequester } from "./types";

export function updateFindingStatus(
  apiRequest: ApiRequester,
  authToken: string,
  findingId: number,
  status: string,
): Promise<StatusUpdate> {
  return apiRequest<StatusUpdate>(`/findings/${findingId}/status`, authToken, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ status }),
  });
}
