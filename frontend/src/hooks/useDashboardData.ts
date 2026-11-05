import { useCallback, useEffect } from "react";
import { fetchDashboardData } from "../api/dashboard";
import { ApiRequestError } from "../api/client";
import type { ApiRequester } from "../api/types";
import type { Asset, AuditEntry, Finding, UserItem, UserRole } from "../types";

interface UseDashboardDataProps {
  token: string | null;
  role: UserRole | "";
  apiRequest: ApiRequester;
  handleLogout: () => void;
  setFindings: (findings: Finding[]) => void;
  setAssets: (assets: Asset[]) => void;
  setAuditLogs: (logs: AuditEntry[]) => void;
  setUsers: (users: UserItem[]) => void;
  setActionMessage: (message: string) => void;
}

export function useDashboardData({
  token,
  role,
  apiRequest,
  handleLogout,
  setFindings,
  setAssets,
  setAuditLogs,
  setUsers,
  setActionMessage,
}: UseDashboardDataProps) {
  const fetchAllData = useCallback(
    (authToken: string) => fetchDashboardData(apiRequest, authToken, role),
    [apiRequest, role],
  );

  useEffect(() => {
    if (!token) return;
    let active = true;
    fetchAllData(token)
      .then(({ findings: nextFindings, assets: nextAssets, auditLogs: nextAuditLogs, users: nextUsers }) => {
        if (!active) return;
        setFindings(nextFindings);
        setAssets(nextAssets);
        setAuditLogs(nextAuditLogs);
        setUsers(nextUsers);
      })
      .catch((fetchError: unknown) => {
        if (active) {
          if (fetchError instanceof ApiRequestError && fetchError.status === 401) handleLogout();
          setActionMessage(fetchError instanceof Error ? fetchError.message : "Unable to load backend data.");
        }
      });
    return () => {
      active = false;
    };
  }, [handleLogout, token, fetchAllData, setFindings, setAssets, setAuditLogs, setUsers, setActionMessage]);

  const refreshAllData = async (authToken: string) => {
    try {
      const { findings: nextFindings, assets: nextAssets, auditLogs: nextAuditLogs, users: nextUsers } =
        await fetchAllData(authToken);
      setFindings(nextFindings);
      setAssets(nextAssets);
      setAuditLogs(nextAuditLogs);
      setUsers(nextUsers);
    } catch (fetchError) {
      if (fetchError instanceof ApiRequestError && fetchError.status === 401) handleLogout();
      setActionMessage(fetchError instanceof Error ? fetchError.message : "Unable to load backend data.");
    }
  };

  return { fetchAllData, refreshAllData };
}
