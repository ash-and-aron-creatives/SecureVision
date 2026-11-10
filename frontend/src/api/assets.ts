import type { Asset } from "../types";
import type { ApiRequester } from "./types";

export type AssetInput = Omit<Asset, "id" | "needs_review">;

export function createAsset(
  apiRequest: ApiRequester,
  authToken: string,
  payload: AssetInput,
): Promise<Asset> {
  return apiRequest<Asset>("/assets", authToken, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}

export function updateAsset(
  apiRequest: ApiRequester,
  authToken: string,
  assetId: number,
  payload: AssetInput,
): Promise<Asset> {
  return apiRequest<Asset>(`/assets/${assetId}`, authToken, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}

export function deleteAsset(
  apiRequest: ApiRequester,
  authToken: string,
  assetId: number,
): Promise<{ deleted: number; name: string }> {
  return apiRequest<{ deleted: number; name: string }>(`/assets/${assetId}`, authToken, {
    method: "DELETE",
  });
}
