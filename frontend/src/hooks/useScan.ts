import { useState } from "react";
import type { FormEvent } from "react";
import { createScan } from "../api/scan";
import type { ApiRequester } from "../api/types";

export function useScan(
  token: string | null,
  apiRequest: ApiRequester,
  setActionMessage: (message: string) => void,
  fetchAllData: (authToken: string) => Promise<unknown>,
  switchTab: (tabId: string) => void,
) {
  const [scanCve, setScanCve] = useState("");
  const [scanAssetId, setScanAssetId] = useState("");
  const [scanCvss, setScanCvss] = useState("9.8");
  const [scanEpss, setScanEpss] = useState("0.0");
  const [scanKev, setScanKev] = useState(false);

  const handleCreateScan = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (!token || !scanAssetId) {
      setActionMessage("Select a backend asset before running a scan.");
      return;
    }
    const cveId = scanCve.trim().toUpperCase();
    const cvssScore = Number(scanCvss);
    const epssPercentile = Number(scanEpss);
    if (!/^CVE-\d{4}-\d{4,}$/.test(cveId)) {
      setActionMessage("CVE ID must look like CVE-2021-44228.");
      return;
    }
    if (!scanCvss.trim() || !Number.isFinite(cvssScore) || cvssScore < 0 || cvssScore > 10) {
      setActionMessage("CVSS score must be between 0 and 10.");
      return;
    }
    if (!scanEpss.trim() || !Number.isFinite(epssPercentile) || epssPercentile < 0 || epssPercentile > 1) {
      setActionMessage("EPSS percentile must be between 0 and 1.");
      return;
    }
    setActionMessage("");
    try {
      const result = await createScan(apiRequest, token, {
        asset_id: Number(scanAssetId),
        cve_id: cveId,
        cvss_score: cvssScore,
        in_kev: scanKev,
        epss_percentile: epssPercentile,
      });
      setActionMessage(`${result.priority_tier} (score ${result.score}/4): ${result.explanation.summary}`);
      await fetchAllData(token);
      switchTab("dashboard");
    } catch (scanError) {
      setActionMessage(scanError instanceof Error ? scanError.message : "Backend scan failed.");
    }
  };

  return {
    scanCve,
    setScanCve,
    scanAssetId,
    setScanAssetId,
    scanCvss,
    setScanCvss,
    scanEpss,
    setScanEpss,
    scanKev,
    setScanKev,
    handleCreateScan,
  };
}
