import { useState } from "react";
import type { FormEvent } from "react";
import { lookupIntel } from "../api/intel";
import { createScan } from "../api/scan";
import type { ApiRequester } from "../api/types";
import type { ScanResult } from "../types";

export function useScan(
  token: string | null,
  apiRequest: ApiRequester,
  setActionMessage: (message: string) => void,
  refreshAllData: (authToken: string) => Promise<boolean>,
  switchTab: (tabId: string) => void,
) {
  const [scanCve, setScanCve] = useState("");
  const [scanAssetId, setScanAssetId] = useState("");
  const [scanCvss, setScanCvss] = useState("");
  const [scanEpss, setScanEpss] = useState("");
  const [scanKev, setScanKev] = useState(false);
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [intelMessage, setIntelMessage] = useState("");
  const [isLookingUpIntel, setIsLookingUpIntel] = useState(false);

  const handleLookupIntel = async () => {
    if (!token) {
      setIntelMessage("Sign in before looking up CVE intelligence.");
      return;
    }
    const cveId = scanCve.trim().toUpperCase();
    if (!/^CVE-\d{4}-\d{4,}$/.test(cveId)) {
      setIntelMessage("CVE ID must look like CVE-2021-44228.");
      return;
    }

    setIsLookingUpIntel(true);
    setIntelMessage("");
    try {
      const intel = await lookupIntel(apiRequest, token, cveId);
      if (!intel.available || intel.cvss === null || intel.epss_percentile === null) {
        setIntelMessage(
          `Intelligence unavailable; scores were not changed. ${intel.errors.join(" ")}`,
        );
        return;
      }
      setScanCvss(String(intel.cvss));
      setScanEpss(String(intel.epss_percentile));
      setIntelMessage(
        `Loaded CVSS ${intel.cvss}, EPSS percentile ${intel.epss_percentile}, and probability ${intel.epss} for ${intel.cve_id}.`,
      );
    } catch (lookupError) {
      setIntelMessage(
        lookupError instanceof Error ? lookupError.message : "CVE intelligence lookup failed.",
      );
    } finally {
      setIsLookingUpIntel(false);
    }
  };

  const handleCreateScan = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (!token || !scanAssetId) {
      setActionMessage("Select a backend asset before running a scan.");
      return;
    }
    const cveId = scanCve.trim().toUpperCase();
    const cvssScore = scanCvss.trim() ? Number(scanCvss) : null;
    const epssPercentile = scanEpss.trim() ? Number(scanEpss) : null;
    if (!/^CVE-\d{4}-\d{4,}$/.test(cveId)) {
      setActionMessage("CVE ID must look like CVE-2021-44228.");
      return;
    }
    if (cvssScore !== null && (!Number.isFinite(cvssScore) || cvssScore < 0 || cvssScore > 10)) {
      setActionMessage("CVSS score must be between 0 and 10.");
      return;
    }
    if (epssPercentile !== null && (!Number.isFinite(epssPercentile) || epssPercentile < 0 || epssPercentile > 1)) {
      setActionMessage("EPSS percentile must be between 0 and 1.");
      return;
    }
    setActionMessage("");
    setScanResult(null);
    try {
      const result = await createScan(apiRequest, token, {
        asset_id: Number(scanAssetId),
        cve_id: cveId,
        cvss_score: cvssScore,
        in_kev: scanKev,
        epss_percentile: epssPercentile,
      });
      const findingLabel = result.action === "updated" ? "Finding updated" : "Finding created";
      const reopenedLabel = result.reopened ? " (reopened)" : "";
      setScanResult(result);
      setActionMessage(
        `${findingLabel}: ${result.final_priority} (${result.priority_source})${reopenedLabel}`,
      );
      await refreshAllData(token);
      switchTab("scan");
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
    scanResult,
    intelMessage,
    isLookingUpIntel,
    handleLookupIntel,
    handleCreateScan,
  };
}
