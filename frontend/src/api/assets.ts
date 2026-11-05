import type { Asset } from "../types";
import type { ApiRequester } from "./types";

export function createAsset(
  apiRequest: ApiRequester,
  authToken: string,
  payload: { name: string; exposure: string; criticality: number },
): Promise<Asset> {
  return apiRequest<Asset>("/assets", authToken, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}
