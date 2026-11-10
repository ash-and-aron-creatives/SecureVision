import type { Dispatch, SetStateAction } from "react";
import { updateFindingStatus } from "../api/findings";
import { ApiRequestError, downloadApiFile } from "../api/client";
import type { ApiRequester } from "../api/types";
import type { DashboardAnalytics, Finding } from "../types";

interface UseFindingsProps {
  token: string | null;
  apiRequest: ApiRequester;
  findings: Finding[];
  setFindings: Dispatch<SetStateAction<Finding[]>>;
  setSelectedFinding: Dispatch<SetStateAction<Finding | null>>;
  searchQuery: string;
  tierFilter: string;
  setActionMessage: (message: string) => void;
  analytics: DashboardAnalytics | null;
  refreshAllData: (authToken: string) => Promise<boolean>;
  handleLogout: () => void;
}

export function useFindings({
  token,
  apiRequest,
  findings,
  setFindings,
  setSelectedFinding,
  searchQuery,
  tierFilter,
  setActionMessage,
  analytics,
  refreshAllData,
  handleLogout,
}: UseFindingsProps) {
  const displayFindings = findings;

  const getTier = (f: Finding): "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN" => {
    const tier = f.priority_tier.toUpperCase();
    if (tier === "CRITICAL" || tier === "HIGH" || tier === "MEDIUM" || tier === "LOW") {
      return tier;
    }
    return "UNKNOWN";
  };

  const toggleFindingStatus = async (finding: Finding) => {
    if (!token) return;
    const status = finding.status.toUpperCase() === "RESOLVED" ? "Open" : "Resolved";
    try {
      const result = await updateFindingStatus(apiRequest, token, finding.id, status);
      setFindings((current) =>
        current.map((item) => item.id === finding.id ? { ...item, status: result.status } : item)
      );
      setSelectedFinding((current) =>
        current?.id === finding.id ? { ...current, status: result.status } : current
      );
      setActionMessage(result.message);
      await refreshAllData(token);
    } catch (statusError) {
      setActionMessage(statusError instanceof Error ? statusError.message : "Unable to update finding status.");
    }
  };

  const criticalCount = analytics?.open_critical_count ??
    displayFindings.filter((f) => getTier(f) === "CRITICAL" && f.status === "Open").length;
  const highCount = analytics?.open_high_count ??
    displayFindings.filter((f) => getTier(f) === "HIGH" && f.status === "Open").length;
  const mediumCount = analytics?.open_medium_count ??
    displayFindings.filter((f) => getTier(f) === "MEDIUM" && f.status === "Open").length;
  const lowCount = analytics?.open_low_count ??
    displayFindings.filter((f) => getTier(f) === "LOW" && f.status === "Open").length;
  const totalCount = analytics?.total_findings ?? displayFindings.length;
  const resolvedCount = analytics?.resolved_findings ??
    displayFindings.filter((f) => (f.status || "").toUpperCase() === "RESOLVED").length;
  const completionPct = analytics
    ? analytics.mitigation_pct
    : totalCount > 0 ? Math.round((resolvedCount / totalCount) * 100) : null;

  const filteredFindings = displayFindings.filter((f) => {
    const matchesTier = tierFilter === "ALL" || getTier(f) === tierFilter;
    const q = searchQuery.toLowerCase().trim();
    const matchesSearch =
      !q ||
      f.cve_id.toLowerCase().includes(q) ||
      f.asset_name.toLowerCase().includes(q) ||
      f.explanation.summary.toLowerCase().includes(q);
    return matchesTier && matchesSearch;
  });

  const reportFailure = (label: string, error: unknown) => {
    if (error instanceof ApiRequestError && error.status === 401) handleLogout();
    const status = error instanceof ApiRequestError ? ` (HTTP ${error.status})` : "";
    const message = error instanceof Error ? error.message : "Unexpected download error.";
    setActionMessage(`${label} failed${status}: ${message}`);
  };

  const exportPriorityCsv = async () => {
    if (!token) return;
    const filters = new URLSearchParams();
    if (tierFilter !== "ALL") filters.set("priority", tierFilter);
    if (searchQuery.trim()) filters.set("q", searchQuery.trim());
    const encodedFilters = filters.toString();
    const query = encodedFilters ? `?${encodedFilters}` : "";
    try {
      await downloadApiFile(`/reports/findings.csv${query}`, token);
      setActionMessage("Backend findings CSV downloaded and recorded in the audit log.");
    } catch (error) {
      reportFailure("CSV export", error);
    }
  };

  const exportExecutiveReport = async () => {
    if (!token) return;
    try {
      await downloadApiFile("/reports/executive.pdf", token);
      setActionMessage("Executive PDF report downloaded and recorded in the audit log.");
    } catch (error) {
      reportFailure("Executive PDF export", error);
    }
  };

  return {
    displayFindings,
    getTier,
    toggleFindingStatus,
    criticalCount,
    highCount,
    mediumCount,
    lowCount,
    totalCount,
    resolvedCount,
    completionPct,
    filteredFindings,
    exportPriorityCsv,
    exportExecutiveReport,
  };
}
