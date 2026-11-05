import { useState } from "react";
import type { FormEvent } from "react";
import { createAsset } from "../api/assets";
import type { ApiRequester } from "../api/types";

export function useAssets(
  token: string | null,
  apiRequest: ApiRequester,
  refreshAllData: (authToken: string) => Promise<boolean>,
  setActionMessage: (message: string) => void,
) {
  const [assetHost, setAssetHost] = useState("");
  const [assetExposure, setAssetExposure] = useState("internet");
  const [assetCrit, setAssetCrit] = useState("5");

  const handleCreateAsset = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (!assetHost || !token) return;
    try {
      const result = await createAsset(apiRequest, token, {
        name: assetHost,
        exposure: assetExposure === "internet" ? "Internet" : "Internal",
        criticality: Number(assetCrit),
      });
      setAssetHost("");
      setActionMessage(`Asset ${result.name} registered by the backend.`);
      await refreshAllData(token);
    } catch (assetError) {
      setActionMessage(assetError instanceof Error ? assetError.message : "Unable to register asset.");
    }
  };

  return { assetHost, setAssetHost, assetExposure, setAssetExposure, assetCrit, setAssetCrit, handleCreateAsset };
}
