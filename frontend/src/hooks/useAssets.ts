import { useState } from "react";
import type { FormEvent } from "react";
import { createAsset, deleteAsset, updateAsset } from "../api/assets";
import type { ApiRequester } from "../api/types";
import type { Asset } from "../types";

export function useAssets(
  token: string | null,
  apiRequest: ApiRequester,
  refreshAllData: (authToken: string) => Promise<boolean>,
  setActionMessage: (message: string) => void,
) {
  const [assetHost, setAssetHost] = useState("");
  const [assetType, setAssetType] = useState("Other");
  const [assetAddress, setAssetAddress] = useState("");
  const [assetOwner, setAssetOwner] = useState("");
  const [assetEnvironment, setAssetEnvironment] = useState("Unknown");
  const [assetExposure, setAssetExposure] = useState("Internet");
  const [assetCrit, setAssetCrit] = useState("5");
  const [editingAssetId, setEditingAssetId] = useState<number | null>(null);

  const resetForm = () => {
    setAssetHost("");
    setAssetType("Other");
    setAssetAddress("");
    setAssetOwner("");
    setAssetEnvironment("Unknown");
    setAssetExposure("Internet");
    setAssetCrit("5");
    setEditingAssetId(null);
  };

  const handleSaveAsset = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (!assetHost || !token) return;
    try {
      const payload = {
        name: assetHost,
        type: assetType,
        ip_or_domain: assetAddress,
        owner: assetOwner,
        environment: assetEnvironment,
        exposure: assetExposure,
        criticality: Number(assetCrit),
      };
      const result = editingAssetId === null
        ? await createAsset(apiRequest, token, payload)
        : await updateAsset(apiRequest, token, editingAssetId, payload);
      setActionMessage(
        editingAssetId === null
          ? `Asset ${result.name} registered by the backend.`
          : `Asset ${result.name} updated.`,
      );
      resetForm();
      await refreshAllData(token);
    } catch (assetError) {
      setActionMessage(assetError instanceof Error ? assetError.message : "Unable to save asset.");
    }
  };

  const handleEditAsset = (asset: Asset) => {
    setEditingAssetId(asset.id);
    setAssetHost(asset.name);
    setAssetType(asset.type);
    setAssetAddress(asset.ip_or_domain);
    setAssetOwner(asset.owner);
    setAssetEnvironment(asset.environment);
    setAssetExposure(asset.exposure);
    setAssetCrit(String(asset.criticality));
  };

  const handleCancelAssetEdit = () => resetForm();

  const handleDeleteAsset = async (asset: Asset) => {
    if (!token || !window.confirm(`Delete asset "${asset.name}"? This cannot be undone.`)) return;
    try {
      await deleteAsset(apiRequest, token, asset.id);
      if (editingAssetId === asset.id) resetForm();
      setActionMessage(`Asset ${asset.name} deleted.`);
      await refreshAllData(token);
    } catch (assetError) {
      setActionMessage(assetError instanceof Error ? assetError.message : "Unable to delete asset.");
    }
  };

  return {
    assetHost, setAssetHost,
    assetType, setAssetType,
    assetAddress, setAssetAddress,
    assetOwner, setAssetOwner,
    assetEnvironment, setAssetEnvironment,
    assetExposure, setAssetExposure,
    assetCrit, setAssetCrit,
    editingAssetId,
    handleSaveAsset, handleEditAsset, handleCancelAssetEdit, handleDeleteAsset,
  };
}
