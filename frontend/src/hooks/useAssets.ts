import { useState } from "react";
import type { FormEvent } from "react";
import { createAsset } from "../api/assets";
import type { ApiRequester } from "../api/types";
import type { Asset } from "../types";

export function useAssets(
  token: string | null,
  apiRequest: ApiRequester,
  setAssets: (update: (current: Asset[]) => Asset[]) => void,
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
      setAssets((current) => [...current, result]);
      setAssetHost("");
      setActionMessage(`Asset ${result.name} registered by the backend.`);
    } catch (assetError) {
      setActionMessage(assetError instanceof Error ? assetError.message : "Unable to register asset.");
    }
  };

  return { assetHost, setAssetHost, assetExposure, setAssetExposure, assetCrit, setAssetCrit, handleCreateAsset };
}
