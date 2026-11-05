"use client";
import React, { useState, useCallback, useSyncExternalStore } from "react";
import { ApiRequestError, requestApi } from "../api/client";
import type {
  Asset,
  AuditEntry,
  Finding,
  LoginResponse,
  UserItem,
  UserRole,
} from "../types";
import { useLogin } from "../hooks/useLogin";
import { useScan } from "../hooks/useScan";
import { useImport } from "../hooks/useImport";
import { useAssets } from "../hooks/useAssets";
import { useUsers } from "../hooks/useUsers";
import { useDashboardData } from "../hooks/useDashboardData";
import { useFindings } from "../hooks/useFindings";
import { useDashboard } from "../hooks/useDashboard";
import { LoginView } from "../components/login/LoginView";
import { DashboardView } from "../components/dashboard/DashboardView";
import { FindingsView } from "../components/findings/FindingsView";
import { FindingDetailsDrawer } from "../components/findings/FindingDetailsDrawer";
import { ScanView } from "../components/scan/ScanView";
import { ImportView } from "../components/import/ImportView";
import { AssetsView } from "../components/assets/AssetsView";
import { AuditView } from "../components/audit/AuditView";
import { UsersView } from "../components/users/UsersView";
import type { SecureAppViewProps } from "../types/views";
const subscribeToNoChanges = () => () => {};
const getClientHydrationSnapshot = () => true;
const getServerHydrationSnapshot = () => false;

function getStoredValue(key: string): string | null {
  return typeof window === "undefined" ? null : localStorage.getItem(key);
}

export function SecureApp({ onBackToHome }: { onBackToHome?: () => void } = {}) {
  const isHydrated = useSyncExternalStore(
    subscribeToNoChanges,
    getClientHydrationSnapshot,
    getServerHydrationSnapshot,
  );
  const [token, setToken] = useState<string | null>(() => getStoredValue("sv_token"));
  const [role, setRole] = useState<UserRole | "">(() => {
    const savedRole = getStoredValue("sv_role");
    return savedRole === "admin" || savedRole === "analyst" || savedRole === "viewer" ? savedRole : "";
  });
  const [currentUser, setCurrentUser] = useState<string>(() => getStoredValue("sv_user") ?? "");

  // Feature data
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [auditLogs, setAuditLogs] = useState<AuditEntry[]>([]);
  const [users, setUsers] = useState<UserItem[]>([]);
  const [actionMessage, setActionMessage] = useState<string>("");

  const {
    activeTab,
    setActiveTab,
    tabAnimKey,
    setTabAnimKey,
    darkMode,
    searchQuery,
    setSearchQuery,
    tierFilter,
    setTierFilter,
    cmdOpen,
    setCmdOpen,
    cmdQuery,
    setCmdQuery,
    mobileMenuOpen,
    setMobileMenuOpen,
    switchTab,
    toggleTheme,
  } = useDashboard(setSelectedFinding);

  const handleLogout = useCallback(() => {
    setToken(null);
    setRole("");
    setCurrentUser("");
    setActiveTab("dashboard");
    setFindings([]);
    setAssets([]);
    setAuditLogs([]);
    setUsers([]);
    if (typeof window !== "undefined") {
      localStorage.removeItem("sv_token");
      localStorage.removeItem("sv_role");
      localStorage.removeItem("sv_user");
    }
  }, [setActiveTab]);

  const apiRequest = useCallback(async <T,>(
    path: string,
    authToken: string | null,
    init: RequestInit = {},
  ): Promise<T> => {
    try {
      return await requestApi<T>(path, authToken, init);
    } catch (requestError) {
      if (requestError instanceof ApiRequestError && requestError.status === 401) {
        handleLogout();
      }
      throw requestError;
    }
  }, [handleLogout]);
  const handleAuthenticated = useCallback((data: LoginResponse, rememberMe: boolean) => {
    setToken(data.access_token);
    setRole(data.role);
    setCurrentUser(data.username);
    if (rememberMe && typeof window !== "undefined") {
      localStorage.setItem("sv_token", data.access_token);
      localStorage.setItem("sv_role", data.role);
      localStorage.setItem("sv_user", data.username);
    } else if (typeof window !== "undefined") {
      localStorage.removeItem("sv_token");
      localStorage.removeItem("sv_role");
      localStorage.removeItem("sv_user");
    }
  }, []);

  const {
    username,
    setUsername,
    password,
    setPassword,
    showPassword,
    setShowPassword,
    rememberMe,
    setRememberMe,
    error,
    handleLogin,
  } = useLogin(apiRequest, handleAuthenticated);

  const { fetchAllData, refreshAllData } = useDashboardData({
    token, role, apiRequest: requestApi, handleLogout, setFindings, setAssets, setAuditLogs, setUsers, setActionMessage,
  });
  const {
    scanCve, setScanCve, scanAssetId, setScanAssetId, scanCvss, setScanCvss, scanEpss, setScanEpss, scanKev, setScanKev,
    handleCreateScan, handleLookupIntel, intelMessage, isLookingUpIntel,
  } = useScan(token, apiRequest, setActionMessage, fetchAllData, switchTab);
  const {
    setCsvFile, importPreview, setImportPreview, handleCsvPreview, handleCsvCommit,
  } = useImport(token, apiRequest, setActionMessage, fetchAllData);
  const { assetHost, setAssetHost, assetExposure, setAssetExposure, assetCrit, setAssetCrit, handleCreateAsset } =
    useAssets(token, apiRequest, setAssets, setActionMessage);
  const { newUsername, setNewUsername, newPassword, setNewPassword, newRole, setNewRole, handleCreateUser } =
    useUsers(token, apiRequest, setUsers, setActionMessage);
  const {
    displayFindings, getTier, toggleFindingStatus, criticalCount, highCount, mediumCount, lowCount,
    totalCount, resolvedCount, completionPct, filteredFindings, exportPriorityCsv, exportExecutiveReport,
  } = useFindings({
    token, apiRequest, findings, setFindings, setSelectedFinding, currentUser, role, searchQuery, tierFilter, setActionMessage,
  });

  // ============================================================================
  // LOGIN VIEW (Quantexa Dark Glassmorphic Portal)
  // ============================================================================
  if (!isHydrated) return null;

  if (!token) {
  return (
    <LoginView
      onBackToHome={onBackToHome}
      error={error}
      username={username}
      setUsername={setUsername}
      password={password}
      setPassword={setPassword}
      showPassword={showPassword}
      setShowPassword={setShowPassword}
      rememberMe={rememberMe}
      setRememberMe={setRememberMe}
      handleLogin={handleLogin}
    />
  );
}

  // ============================================================================
  // AUTHENTICATED DASHBOARD VIEW (Responsive Windows Desktop, Tablet & Phone)
  // ============================================================================
  const menuItems = [
    { id: "dashboard", label: "Dashboard", badge: null, icon: "grid" },
    { id: "queue", label: "Priority Queue", badge: `${criticalCount + highCount}+`, icon: "tasks" },
    ...(role === "admin" || role === "analyst" ? [
      { id: "scan", label: "New Scan", badge: null, icon: "scan" },
      { id: "import", label: "Import CSV", badge: null, icon: "upload" },
    ] : []),
    { id: "assets", label: "Assets", badge: null, icon: "server" },
    ...(role === "admin" ? [
      { id: "audit", label: "Audit Log", badge: null, icon: "shield" },
      { id: "users", label: "Users (RBAC)", badge: null, icon: "users" },
    ] : []),
  ];

  const weeklyBars = [
    { day: "S", height: "58%", type: "striped", label: "18" },
    { day: "M", height: "82%", type: "purple", label: "34" },
    { day: "T", height: "74%", type: "cyan", label: "79%" },
    { day: "W", height: "96%", type: "deep", label: "48" },
    { day: "T", height: "88%", type: "striped", label: "39" },
    { day: "F", height: "66%", type: "striped", label: "24" },
    { day: "S", height: "72%", type: "striped", label: "29" },
  ];

  const shellBg = darkMode
    ? "bg-gradient-to-br from-[#120629] via-[#1B0B3B] to-[#0B031D] text-white"
    : "bg-[#F4F6FA] text-slate-900";
  const surfaceCard = darkMode
    ? "bg-[#221046]/80 backdrop-blur-2xl border-white/10 text-white shadow-[0_12px_35px_rgba(0,0,0,0.45)]"
    : "bg-white border-slate-100 text-slate-900 shadow-[0_8px_30px_rgb(0,0,0,0.03)]";
  const subSurfaceCard = darkMode
    ? "bg-[#170934]/80 border-white/10 text-white"
    : "bg-[#F8FAFC] border-slate-200/80 text-slate-900";
  const itemSurface = darkMode
    ? "bg-[#24114D]/90 border-white/10 hover:border-[#00E5C4]/50 text-white"
    : "bg-white border-slate-100 hover:border-[#8121D7]/40 text-slate-800";
  const headingColor = darkMode ? "text-white" : "text-[#1D0C3B]";
  const mutedText = darkMode ? "text-white/55" : "text-slate-400";
  const viewProps: SecureAppViewProps = {
    activeTab, tabAnimKey, surfaceCard, headingColor, mutedText, switchTab, darkMode, exportExecutiveReport,
    criticalCount, highCount, mediumCount, lowCount, subSurfaceCard, itemSurface, getTier, weeklyBars,
    completionPct, totalCount, resolvedCount, displayFindings, setTierFilter, tierFilter, exportPriorityCsv, filteredFindings,
    toggleFindingStatus, handleCreateScan, handleLookupIntel, intelMessage, isLookingUpIntel,
    scanCve, setScanCve, scanAssetId, setScanAssetId, assets,
    scanCvss, setScanCvss, scanEpss, setScanEpss, scanKev, setScanKev, handleCsvPreview, setCsvFile,
    importPreview, setImportPreview, handleCsvCommit, handleCreateAsset, assetHost, setAssetHost, assetExposure, setAssetExposure,
    assetCrit, setAssetCrit, role, auditLogs, handleCreateUser, newUsername, setNewUsername, newPassword,
    setNewPassword, newRole, setNewRole, users, selectedFinding, setSelectedFinding,
  };

  return (
    <div className={`min-h-screen ${shellBg} font-sans p-2.5 sm:p-4 lg:p-5 pb-20 lg:pb-5 flex flex-col lg:flex-row gap-4 lg:gap-5 overflow-x-hidden transition-colors duration-300 relative`}>
      <style>{`
        @keyframes svTabEnter {
          0% { opacity: 0; transform: translateY(18px) scale(0.985); }
          100% { opacity: 1; transform: translateY(0) scale(1); }
        }
        @keyframes svCardPop {
          0% { opacity: 0; transform: translateY(24px) scale(0.96); }
          100% { opacity: 1; transform: translateY(0) scale(1); }
        }
        @keyframes svBarGrow {
          0% { transform: scaleY(0.05); opacity: 0.2; }
          100% { transform: scaleY(1); opacity: 1; }
        }
        @keyframes svGaugeSweep {
          0% { stroke-dashoffset: 251.2; }
        }
        @keyframes svDrawerSlide {
          0% { opacity: 0; transform: translateX(100%); }
          100% { opacity: 1; transform: translateX(0); }
        }
        .sv-tab-transition {
          animation: svTabEnter 0.45s cubic-bezier(0.16, 1, 0.3, 1) forwards;
        }
        .sv-card-pop {
          opacity: 0;
          animation: svCardPop 0.55s cubic-bezier(0.16, 1, 0.3, 1) forwards;
        }
        .sv-bar-grow {
          transform-origin: bottom;
          animation: svBarGrow 0.75s cubic-bezier(0.16, 1, 0.3, 1) forwards;
        }
        .sv-gauge-arc {
          animation: svGaugeSweep 1.1s cubic-bezier(0.16, 1, 0.3, 1) forwards;
        }
        .sv-drawer-enter {
          animation: svDrawerSlide 0.32s cubic-bezier(0.16, 1, 0.3, 1) forwards;
        }
        .sv-striped-bar {
          background-image: repeating-linear-gradient(
            -45deg,
            rgba(129, 33, 215, 0.24),
            rgba(129, 33, 215, 0.24) 5px,
            rgba(0, 229, 196, 0.10) 5px,
            rgba(0, 229, 196, 0.10) 10px
          );
          border: 1px dashed rgba(129, 33, 215, 0.40);
        }
      `}</style>

      {/* MOBILE / TABLET BACKDROP OVERLAY */}
      {mobileMenuOpen && (
        <div
          onClick={() => setMobileMenuOpen(false)}
          className="fixed inset-0 bg-black/60 backdrop-blur-xs z-40 lg:hidden"
        />
      )}

      {/* LEFT SIDEBAR (Slide-Over Drawer on Phone/Tablet, Static Card on Desktop) */}
      <aside
        className={`fixed lg:static inset-y-0 left-0 z-50 w-72 lg:w-64 shrink-0 rounded-none lg:rounded-3xl p-6 flex flex-col justify-between border-r lg:border transition-transform duration-300 overflow-y-auto ${surfaceCard} ${
          mobileMenuOpen ? "translate-x-0" : "-translate-x-full lg:translate-x-0"
        }`}
      >
        <div>
          <div className="flex items-center justify-between mb-8 px-1">
            <div
              onClick={() => switchTab("dashboard")}
              className="flex items-center gap-2.5 cursor-pointer group"
            >
              <svg viewBox="0 0 120 100" className="w-10 h-9 shrink-0 drop-shadow-sm group-hover:scale-110 group-hover:rotate-2 transition-transform duration-300" fill="none" xmlns="http://www.w3.org/2000/svg">
                <defs>
                  <linearGradient id="sideWingTop" x1="6" y1="20" x2="100" y2="80" gradientUnits="userSpaceOnUse">
                    <stop offset="0%" stopColor="#00E5C4"/>
                    <stop offset="55%" stopColor="#3B82F6"/>
                    <stop offset="100%" stopColor="#8121D7"/>
                  </linearGradient>
                  <linearGradient id="sideShieldGuard" x1="22" y1="35" x2="105" y2="95" gradientUnits="userSpaceOnUse">
                    <stop offset="0%" stopColor="#00E5C4"/>
                    <stop offset="45%" stopColor="#6D28D9"/>
                    <stop offset="100%" stopColor="#3B096C"/>
                  </linearGradient>
                </defs>
                <path d="M 22 40 L 42 40 C 50 40 55 46 59 56 L 73 88 L 93 34 C 96 58 87 82 73 96 C 55 82 45 62 39 50 L 28 50 Z" fill="url(#sideShieldGuard)" />
                <path d="M 6 22 L 56 22 C 66 22 72 28 75 36 L 73 66 L 94 20 L 106 20 L 73 86 L 56 46 C 52 36 46 32 36 32 L 14 32 Z" fill="url(#sideWingTop)" />
              </svg>
              <div className="text-xl font-extrabold tracking-tight leading-none">
                <span className={headingColor}>Secure</span>
                <span className="text-[#00B89E]">Vision</span>
              </div>
            </div>
            <button
              type="button"
              onClick={() => setMobileMenuOpen(false)}
              className="lg:hidden w-8 h-8 rounded-full bg-slate-100 dark:bg-white/10 flex items-center justify-center text-sm font-bold"
            >
              ✕
            </button>
          </div>

          <div className="mb-7">
            <p className={`text-[11px] font-bold uppercase tracking-widest px-3 mb-3 ${mutedText}`}>
              MENU
            </p>
            <nav className="space-y-1.5">
              {menuItems.map((item) => {
                const isActive = activeTab === item.id;
                return (
                  <button
                    key={item.id}
                    onClick={() => switchTab(item.id)}
                    className={`w-full flex items-center justify-between px-3.5 py-2.5 rounded-xl text-sm font-semibold transition-all duration-200 relative cursor-pointer group ${
                      isActive
                        ? darkMode
                          ? "text-white bg-gradient-to-r from-[#8121D7]/35 via-[#00E5C4]/20 to-transparent font-bold translate-x-1"
                          : "text-[#2B125A] bg-gradient-to-r from-[#8121D7]/15 via-[#00E5C4]/10 to-transparent font-bold translate-x-1 shadow-2xs"
                        : darkMode
                        ? "text-white/65 hover:text-white hover:bg-white/5 hover:translate-x-1"
                        : "text-slate-500 hover:text-slate-800 hover:bg-slate-50 hover:translate-x-1"
                    }`}
                  >
                    {isActive && (
                      <span className="absolute left-0 top-1.5 bottom-1.5 w-1.5 rounded-r-full bg-gradient-to-b from-[#8121D7] to-[#00E5C4]"></span>
                    )}
                    <div className="flex items-center gap-3">
                      <span className={`transition-transform duration-200 group-hover:scale-110 ${isActive ? (darkMode ? "text-[#00E5C4]" : "text-[#8121D7]") : mutedText}`}>
                        {item.icon === "grid" && (
                          <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 24 24"><path d="M4 4h6v6H4V4zm10 0h6v6h-6V4zM4 14h6v6H4v-6zm10 0h6v6h-6v-6z"/></svg>
                        )}
                        {item.icon === "tasks" && (
                          <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4"/></svg>
                        )}
                        {item.icon === "scan" && (
                          <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/></svg>
                        )}
                        {item.icon === "upload" && (
                          <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12"/></svg>
                        )}
                        {item.icon === "server" && (
                          <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2"/></svg>
                        )}
                        {item.icon === "shield" && (
                          <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>
                        )}
                        {item.icon === "users" && (
                          <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0z"/></svg>
                        )}
                      </span>
                      <span>{item.label}</span>
                    </div>
                    {item.badge && (
                      <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-[#2B125A] text-[#00E5C4] border border-[#00E5C4]/30 animate-pulse">
                        {item.badge}
                      </span>
                    )}
                  </button>
                );
              })}
            </nav>
          </div>

          <div>
            <p className={`text-[11px] font-bold uppercase tracking-widest px-3 mb-3 ${mutedText}`}>
              GENERAL
            </p>
            <div className="space-y-1.5">
              {onBackToHome && (
                <button
                  onClick={onBackToHome}
                  className={`w-full flex items-center gap-3 px-3.5 py-2.5 rounded-xl text-sm font-semibold transition-all cursor-pointer hover:translate-x-1 ${
                    darkMode ? "text-white/65 hover:text-[#00E5C4] hover:bg-white/5" : "text-slate-500 hover:text-[#8121D7] hover:bg-slate-50"
                  }`}
                >
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6" />
                  </svg>
                  <span>Landing Page</span>
                </button>
              )}
              <button
                onClick={handleLogout}
                className="w-full flex items-center gap-3 px-3.5 py-2.5 rounded-xl text-sm font-semibold text-rose-500 hover:bg-rose-500/10 hover:translate-x-1 transition-all cursor-pointer"
              >
                <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
                </svg>
                <span>Logout</span>
              </button>
            </div>
          </div>
        </div>

      </aside>

      {/* MAIN CONTENT AREA */}
      <div className="flex-1 flex flex-col gap-5 min-w-0">
        {/* TOP SEARCH, THEME TOGGLE, EXPORT & PROFILE HEADER BAR */}
        <header className={`rounded-2xl sm:rounded-3xl px-3.5 sm:px-6 py-3 sm:py-3.5 flex items-center justify-between gap-2.5 sm:gap-4 border transition-colors duration-300 ${surfaceCard}`}>
          <div className="flex items-center gap-2.5 flex-1 min-w-0">
            <button
              type="button"
              onClick={() => setMobileMenuOpen(true)}
              aria-label="Open Navigation Menu"
              className={`lg:hidden w-10 h-10 rounded-xl flex items-center justify-center shrink-0 border cursor-pointer ${
                darkMode
                  ? "bg-[#15082E] border-white/15 text-[#00E5C4]"
                  : "bg-[#F4F6FA] border-slate-200/80 text-[#2B125A]"
              }`}
            >
              <svg className="w-5 h-5" fill="none" stroke="currentColor" strokeWidth="2.2" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" d="M4 6h16M4 12h16M4 18h16" />
              </svg>
            </button>

            <div className="relative flex-1 max-w-md min-w-0">
              <span className={`absolute inset-y-0 left-0 pl-3.5 sm:pl-4 flex items-center ${mutedText}`}>
                <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                </svg>
              </span>
              <input
                type="text"
                placeholder="Search CVE, asset, or explanation..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className={`w-full pl-10 sm:pl-11 pr-14 sm:pr-20 py-2.5 rounded-full text-xs sm:text-sm focus:outline-none transition-all ${
                  darkMode
                    ? "bg-[#15082E] border border-white/10 focus:border-[#00E5C4] text-white placeholder-white/40"
                    : "bg-[#F4F6FA] border border-transparent focus:border-[#8121D7]/40 focus:bg-white text-slate-800 placeholder-slate-400"
                }`}
              />
              <button
                type="button"
                onClick={() => setCmdOpen(true)}
                title="Open Command Palette (Ctrl+K or ⌘F)"
                className={`hidden sm:block absolute inset-y-1.5 right-2 px-2.5 rounded-full text-[11px] font-bold border transition-colors cursor-pointer ${
                  darkMode
                    ? "bg-white/10 text-[#00E5C4] border-white/15 hover:bg-white/20"
                    : "bg-white text-slate-500 border-slate-200 hover:border-[#8121D7] hover:text-[#8121D7] shadow-2xs"
                }`}
              >
                ⌘F
              </button>
            </div>
          </div>

          <div className="flex items-center gap-2 sm:gap-2.5 shrink-0">
            <button
              onClick={toggleTheme}
              title={darkMode ? "Switch to Crisp White Mode" : "Switch to Quantexa Dark Glass Mode"}
              className={`px-3 sm:px-3.5 h-10 rounded-full flex items-center gap-2 text-xs font-bold border transition-all cursor-pointer ${
                darkMode
                  ? "bg-[#15082E] border-[#00E5C4]/40 text-[#00E5C4] hover:bg-[#00E5C4]/15"
                  : "bg-[#F4F6FA] border-slate-200/80 text-[#2B125A] hover:bg-[#8121D7]/10"
              }`}
            >
              {darkMode ? (
                <>
                  <svg className="w-4 h-4 text-[#00E5C4]" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z" />
                  </svg>
                  <span className="hidden md:inline">Light Mode</span>
                </>
              ) : (
                <>
                  <svg className="w-4 h-4 text-[#8121D7]" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z" />
                  </svg>
                  <span className="hidden md:inline">Dark Glass</span>
                </>
              )}
            </button>

            <button
              onClick={() => {
                setTabAnimKey((prev) => prev + 1);
                if (token) refreshAllData(token);
              }}
              title="Replay Motion & Refresh Telemetry"
              className={`w-10 h-10 rounded-full flex items-center justify-center transition-all hover:rotate-180 duration-500 cursor-pointer ${
                darkMode
                  ? "bg-[#15082E] text-white/80 hover:text-[#00E5C4] border border-white/10"
                  : "bg-[#F4F6FA] text-slate-600 hover:text-[#8121D7]"
              }`}
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
              </svg>
            </button>

            <button
              onClick={exportExecutiveReport}
              title="Download Executive Audit Report"
              className={`w-10 h-10 rounded-full flex items-center justify-center transition-colors relative cursor-pointer ${
                darkMode
                  ? "bg-[#15082E] text-white/80 hover:text-[#00E5C4] border border-white/10"
                  : "bg-[#F4F6FA] text-slate-600 hover:text-[#8121D7]"
              }`}
            >
              <span className="w-2 h-2 rounded-full bg-[#00E5C4] absolute top-2.5 right-2.5 animate-ping"></span>
              <span className="w-2 h-2 rounded-full bg-[#00E5C4] absolute top-2.5 right-2.5"></span>
              <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
              </svg>
            </button>

            <div className="flex items-center gap-3 pl-1 sm:pl-2">
              <div className="w-10 h-10 rounded-full bg-gradient-to-tr from-[#8121D7] to-[#00E5C4] text-white font-extrabold text-sm flex items-center justify-center shadow-sm">
                {currentUser.slice(0, 2).toUpperCase()}
              </div>
              <div className="hidden sm:block leading-tight">
                <p className={`text-sm font-bold capitalize ${headingColor}`}>{currentUser}</p>
                <p className={`text-xs ${mutedText}`}>{role.toUpperCase()}@securevision.io</p>
              </div>
            </div>
          </div>
        </header>

        {actionMessage && (
          <div className="bg-gradient-to-r from-[#8121D7] to-[#1ABDD6] text-white px-5 py-3 rounded-2xl text-xs font-semibold flex items-center justify-between shadow-sm sv-tab-transition">
            <span>{actionMessage}</span>
            <button onClick={() => setActionMessage("")} className="text-white/80 hover:text-white font-bold">✕</button>
          </div>
        )}

        {/* =================================================================== */}
        {/* TAB 1: ANIMATED MOTION BENTO DASHBOARD                              */}
        {/* =================================================================== */}
        <DashboardView {...viewProps} />

        {/* =================================================================== */}
        {/* TAB 2: FULL PRIORITY QUEUE TABLE                                    */}
        {/* =================================================================== */}
        <FindingsView {...viewProps} />

        {/* =================================================================== */}
        {/* TAB 3: NEW SCAN EVALUATION                                          */}
        {/* =================================================================== */}
        <ScanView {...viewProps} />

        {/* =================================================================== */}
        {/* TAB 4: IMPORT CSV                                                   */}
        {/* =================================================================== */}
        <ImportView {...viewProps} />

        {/* =================================================================== */}
        {/* TAB 5: ASSETS INVENTORY                                             */}
        {/* =================================================================== */}
        <AssetsView {...viewProps} />

        {/* =================================================================== */}
        {/* TAB 6: AUDIT LOG                                                    */}
        {/* =================================================================== */}
        <AuditView {...viewProps} />

        {/* =================================================================== */}
        {/* TAB 7: USERS (RBAC)                                                 */}
        {/* =================================================================== */}
        <UsersView {...viewProps} />
      </div>

      {/* MOBILE & TABLET BOTTOM NAVIGATION BAR (< lg) */}
      <nav
        className={`lg:hidden fixed bottom-0 left-0 right-0 z-30 px-3 py-2 border-t flex items-center justify-around backdrop-blur-xl ${
          darkMode
            ? "bg-[#15082E]/95 border-white/15 text-white"
            : "bg-white/95 border-slate-200 text-slate-700 shadow-[0_-4px_20px_rgba(0,0,0,0.06)]"
        }`}
      >
        {[
          { id: "dashboard", label: "Dashboard" },
          { id: "queue", label: "Queue" },
          ...(role === "admin" || role === "analyst" ? [{ id: "scan", label: "Scan" }] : []),
          { id: "assets", label: "Assets" },
          ...(role === "admin" ? [{ id: "audit", label: "Audit" }] : []),
        ].map((tab) => {
          const isAct = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => switchTab(tab.id)}
              className={`flex flex-col items-center gap-0.5 px-3 py-1 rounded-xl text-[10px] font-bold transition-all cursor-pointer ${
                isAct
                  ? "text-[#00B89E] scale-105"
                  : darkMode
                  ? "text-white/60 hover:text-white"
                  : "text-slate-400 hover:text-slate-800"
              }`}
            >
              <span className={`w-1.5 h-1.5 rounded-full mb-0.5 ${isAct ? "bg-[#00E5C4]" : "bg-transparent"}`}></span>
              <span>{tab.label}</span>
            </button>
          );
        })}
      </nav>

      {/* Backend scoring explanation drawer */}
      <FindingDetailsDrawer {...viewProps} />

      {/* INTERACTIVE COMMAND PALETTE MODAL (⌘F / Ctrl+K) */}
      {cmdOpen && (
        <div
          onClick={() => setCmdOpen(false)}
          className="fixed inset-0 bg-black/60 backdrop-blur-xs z-50 flex items-start justify-center pt-20 px-4"
        >
          <div
            onClick={(e) => e.stopPropagation()}
            className="w-full max-w-xl rounded-3xl bg-[#1A0B3B] border border-white/20 text-white shadow-2xl overflow-hidden sv-tab-transition"
          >
            <div className="p-4 border-b border-white/10 flex items-center gap-3">
              <svg className="w-5 h-5 text-[#00E5C4]" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
              </svg>
              <input
                type="text"
                autoFocus
                placeholder="Type a CVE ID, hostname, or command (e.g. 'dark', 'export', 'scan')..."
                value={cmdQuery}
                onChange={(e) => setCmdQuery(e.target.value)}
                className="w-full bg-transparent text-sm text-white placeholder-white/40 focus:outline-none"
              />
              <button
                onClick={() => setCmdOpen(false)}
                className="text-xs px-2 py-1 rounded bg-white/10 text-white/60 hover:text-white"
              >
                ESC
              </button>
            </div>

            <div className="p-3 max-h-80 overflow-y-auto space-y-1 text-xs">
              <p className="px-3 py-1 text-[10px] font-bold uppercase tracking-wider text-white/40">
                Quick Actions
              </p>
              <button
                onClick={() => { toggleTheme(); setCmdOpen(false); }}
                className="w-full flex items-center justify-between px-3 py-2.5 rounded-xl hover:bg-white/10 transition-colors cursor-pointer text-left"
              >
                <span>Toggle Dark Glass / Crisp White Theme</span>
                <span className="text-[#00E5C4] font-mono">Theme</span>
              </button>
              <button
                onClick={() => { exportPriorityCsv(); setCmdOpen(false); }}
                className="w-full flex items-center justify-between px-3 py-2.5 rounded-xl hover:bg-white/10 transition-colors cursor-pointer text-left"
              >
                <span>Export Priority Queue to CSV</span>
                <span className="text-[#00E5C4] font-mono">CSV</span>
              </button>
              <button
                onClick={() => { exportExecutiveReport(); setCmdOpen(false); }}
                className="w-full flex items-center justify-between px-3 py-2.5 rounded-xl hover:bg-white/10 transition-colors cursor-pointer text-left"
              >
                <span>Download Executive Compliance Report</span>
                <span className="text-[#00E5C4] font-mono">Report</span>
              </button>

              <p className="px-3 pt-3 pb-1 text-[10px] font-bold uppercase tracking-wider text-white/40">
                View backend scoring explanation
              </p>
              {displayFindings
                .filter(
                  (f) =>
                    !cmdQuery ||
                    f.cve_id.toLowerCase().includes(cmdQuery.toLowerCase()) ||
                    f.asset_name.toLowerCase().includes(cmdQuery.toLowerCase())
                )
                .slice(0, 5)
                .map((f) => (
                  <button
                    key={f.id}
                    onClick={() => {
                      setSelectedFinding(f);
                      setCmdOpen(false);
                    }}
                    className="w-full flex items-center justify-between px-3 py-2.5 rounded-xl hover:bg-white/10 transition-colors cursor-pointer text-left"
                  >
                    <div>
                      <span className="font-bold text-white">{f.cve_id}</span>
                      <span className="text-white/50 ml-2">on {f.asset_name}</span>
                    </div>
                    <span className="px-2 py-0.5 rounded bg-[#00E5C4]/15 text-[#00E5C4] font-bold">
                      Score {f.score}/4 →
                    </span>
                  </button>
                ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
