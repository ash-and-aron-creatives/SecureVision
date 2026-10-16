"use client";
import React, { useState, useEffect } from "react";
import axios from "axios";
import {
  Shield, Server, Search, LogOut, AlertTriangle,
  FileText, UploadCloud, Eye, X, PlusCircle, CheckCircle2, Filter, Users, Trash2
} from "lucide-react";
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell } from "recharts";

const API_URL = "http://127.0.0.1:8000";

export default function SecureVisionApp() {
  const [token, setToken] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState("admin");
  const [view, setView] = useState("dashboard");
  const [usersList, setUsersList] = useState<any[]>([]);
  const [newUsername, setNewUsername] = useState("");
  const [newUserPassword, setNewUserPassword] = useState("");
  const [newUserRole, setNewUserRole] = useState("analyst");
  const [userMsg, setUserMsg] = useState("");
  const [userErr, setUserErr] = useState("");

  // Data State
  const [assets, setAssets] = useState<any[]>([]);
  const [findings, setFindings] = useState<any[]>([]);
  const [counts, setCounts] = useState<Record<string, number>>({ Critical: 0, High: 0, Medium: 0, Low: 0 });
  const [totalFindings, setTotalFindings] = useState(0);
  const [page, setPage] = useState(1);
  const [pages, setPages] = useState(1);
  const [auditLogs, setAuditLogs] = useState<any[]>([]);

  // Filter & Search State (Step 2)
  const [filterPriority, setFilterPriority] = useState("");
  const [filterStatus, setFilterStatus] = useState("");
  const [filterAssetId, setFilterAssetId] = useState("");
  const [searchQuery, setSearchQuery] = useState("");
  const [sortBy, setSortBy] = useState("priority");

  // Finding Detail Modal State (Step 2)
  const [selectedFinding, setSelectedFinding] = useState<any | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);

  const [exporting, setExporting] = useState<"csv" | "pdf" | null>(null);

  const downloadReport = async (path: string, params: Record<string, string | number | undefined>, kind: "csv" | "pdf") => {
    setExporting(kind);
    try {
      const qs = new URLSearchParams();
      Object.entries(params).forEach(([k, v]) => {
        if (v !== undefined && v !== "" && v !== null) qs.set(k, String(v));
      });
      const res = await fetch(`${API_URL}${path}${qs.toString() ? `?${qs}` : ""}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!res.ok) throw new Error(`Export failed (${res.status})`);
      const blob = await res.blob();
      const cd = res.headers.get("Content-Disposition") ?? "";
      const filename = /filename="?([^"]+)"?/.exec(cd)?.[1] ?? `securevision-report.${kind}`;
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      fetchData();
    } catch (e: any) {
      alert(e instanceof Error ? e.message : "Export failed");
    } finally {
      setExporting(null);
    }
  };

  const handleExportCsv = () =>
    downloadReport("/reports/findings.csv", {
      priority: filterPriority,
      status: filterStatus,
      asset_id: filterAssetId,
      q: searchQuery,
      sort: sortBy,
    }, "csv");

  const handleExportPdf = () => downloadReport("/reports/executive.pdf", {}, "pdf");
  // Manual Scan State
  const [scanAsset, setScanAsset] = useState("");
  const [cveId, setCveId] = useState("");
  const [cvss, setCvss] = useState("");
  const [epss, setEpss] = useState("");
  const [inKev, setInKev] = useState(false);
  const [isFetchingIntel, setIsFetchingIntel] = useState(false);
  const [scanResult, setScanResult] = useState<any>(null);
  const [scanError, setScanError] = useState("");

  // Asset Creation State
  const [newAssetName, setNewAssetName] = useState("");
  const [newAssetExposure, setNewAssetExposure] = useState("Internet");
  const [newAssetCrit, setNewAssetCrit] = useState(4);
  const [assetMsg, setAssetMsg] = useState("");

  // Import CSV State (Step 1)
  const [importFile, setImportFile] = useState<File | null>(null);
  const [importRows, setImportRows] = useState<any[]>([]);
  const [importSummary, setImportSummary] = useState<any>(null);
  const [importResult, setImportResult] = useState<any>(null);
  const [importError, setImportError] = useState("");
  const [importBusy, setImportBusy] = useState(false);

  useEffect(() => {
    if (token) {
      fetchData();
    }
  }, [token, view, filterPriority, filterStatus, filterAssetId, searchQuery, sortBy, page]);

  const fetchData = async () => {
    try {
      const hdrs = { Authorization: `Bearer ${token}` };
      const params = new URLSearchParams();
      if (filterPriority) params.append("priority", filterPriority);
      if (filterStatus) params.append("status", filterStatus);
      if (filterAssetId) params.append("asset_id", filterAssetId);
      if (searchQuery) params.append("q", searchQuery);
      params.append("sort", sortBy);
      params.append("page", String(page));
      params.append("page_size", "15");

      const [assRes, findRes, auditRes] = await Promise.all([
        axios.get(`${API_URL}/assets`, { headers: hdrs }),
        axios.get(`${API_URL}/findings?${params.toString()}`, { headers: hdrs }),
        axios.get(`${API_URL}/audit`, { headers: hdrs }),
      ]);

      setAssets(assRes.data);
      if (!scanAsset && assRes.data.length > 0) {
        setScanAsset(String(assRes.data[0].id));
      }

      setFindings(findRes.data.items || []);
      setCounts(findRes.data.counts || { Critical: 0, High: 0, Medium: 0, Low: 0 });
      setTotalFindings(findRes.data.total || 0);
      setPages(findRes.data.pages || 1);
      setAuditLogs(auditRes.data || []);
      if (role === "admin") {
        const uRes = await axios.get(`${API_URL}/users`, { headers: hdrs }).catch(() => ({ data: [] }));
        setUsersList(uRes.data || []);
      }
    } catch (e) {
      console.error("Fetch error", e);
    }
  };

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const formData = new URLSearchParams();
      formData.append("username", username);
      formData.append("password", password);
      const res = await axios.post(`${API_URL}/token`, formData, {
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
      });
      setToken(res.data.access_token);
      setRole(res.data.role || "admin");
    } catch {
      alert("Login failed. Use admin / password123");
    }
  };

  const openFindingDetail = async (id: number) => {
    setDetailLoading(true);
    try {
      const res = await axios.get(`${API_URL}/findings/${id}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      setSelectedFinding(res.data);
    } catch (e) {
      console.error("Failed to load finding details", e);
    } finally {
      setDetailLoading(false);
    }
  };

  const handleStatusChange = async (findingId: number, newStatus: string) => {
    try {
      await axios.put(
        `${API_URL}/findings/${findingId}/status`,
        { status: newStatus },
        { headers: { Authorization: `Bearer ${token}` } }
      );
      fetchData();
      if (selectedFinding && selectedFinding.id === findingId) {
        openFindingDetail(findingId);
      }
    } catch {
      alert("Failed to update status.");
    }
  };

  const handleFetchIntel = async () => {
    if (!cveId.trim()) return;
    setIsFetchingIntel(true);
    setScanError("");
    try {
      const res = await axios.get(`${API_URL}/intel/${cveId.trim().toUpperCase()}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      setCvss(String(res.data.cvss ?? 7.5));
      setEpss(String(res.data.epss ?? 0.5));
      setInKev(Boolean(res.data.in_kev));
    } catch {
      setScanError("Could not fetch live intel for that CVE. You can still enter values manually.");
    } finally {
      setIsFetchingIntel(false);
    }
  };

  const handleRunScan = async (e: React.FormEvent) => {
    e.preventDefault();
    setScanError("");
    setScanResult(null);
    try {
      const res = await axios.post(
        `${API_URL}/scan`,
        {
          asset_id: Number(scanAsset),
          cve_id: cveId.trim().toUpperCase(),
          cvss_score: parseFloat(cvss) || 0.0,
          epss_percentile: parseFloat(epss) || 0.0,
          in_kev: inKev,
        },
        { headers: { Authorization: `Bearer ${token}` } }
      );
      setScanResult(res.data);
      fetchData();
    } catch (err: any) {
      setScanError(err?.response?.data?.detail || "Scan failed.");
    }
  };

  const handleCreateUser = async (e: React.FormEvent) => {
    e.preventDefault();
    setUserMsg(""); setUserErr("");
    try {
      await axios.post(`${API_URL}/users`, { username: newUsername, password: newUserPassword, role: newUserRole }, { headers: { Authorization: `Bearer ${token}` } });
      setNewUsername(""); setNewUserPassword(""); setNewUserRole("analyst");
      setUserMsg("User created and logged to Audit Trail!");
      fetchData();
    } catch (err: any) {
      setUserErr(err?.response?.data?.detail || "Failed to create user.");
    }
  };

  const handleRoleChange = async (userId: number, updatedRole: string) => {
    setUserMsg(""); setUserErr("");
    try {
      await axios.put(`${API_URL}/users/${userId}/role`, { role: updatedRole }, { headers: { Authorization: `Bearer ${token}` } });
      setUserMsg("Role updated!");
      fetchData();
    } catch (err: any) {
      setUserErr(err?.response?.data?.detail || "Failed to update role.");
    }
  };

  const handleDeleteUser = async (userId: number) => {
    setUserMsg(""); setUserErr("");
    try {
      await axios.delete(`${API_URL}/users/${userId}`, { headers: { Authorization: `Bearer ${token}` } });
      setUserMsg("User deleted.");
      fetchData();
    } catch (err: any) {
      setUserErr(err?.response?.data?.detail || "Failed to delete user.");
    }
  };
  const handleCreateAsset = async (e: React.FormEvent) => {
    e.preventDefault();
    setAssetMsg("");
    try {
      await axios.post(
        `${API_URL}/assets`,
        { name: newAssetName, exposure: newAssetExposure, criticality: Number(newAssetCrit) },
        { headers: { Authorization: `Bearer ${token}` } }
      );
      setNewAssetName("");
      setAssetMsg("Asset added and logged to Audit Trail!");
      fetchData();
    } catch (err: any) {
      setAssetMsg(err?.response?.data?.detail || "Failed to add asset.");
    }
  };

  const runImport = async (path: string, after: (d: any) => void) => {
    if (!importFile) return;
    setImportBusy(true);
    setImportError("");
    try {
      const form = new FormData();
      form.append("file", importFile);
      const res = await axios.post(`${API_URL}${path}`, form, {
        headers: { "Content-Type": "multipart/form-data", Authorization: `Bearer ${token}` },
      });
      after(res.data);
      fetchData();
    } catch (e: any) {
      setImportError(e?.response?.data?.detail ?? "Upload failed.");
    } finally {
      setImportBusy(false);
    }
  };

  const downloadProblems = () => {
    const blob = new Blob([importResult!.problems_csv], { type: "text/csv" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "import_problems.csv";
    a.click();
  };

  const tierBadge = (tier: string) => {
    if (tier === "Critical") return "bg-red-100 text-red-800 border-red-200";
    if (tier === "High") return "bg-orange-100 text-orange-800 border-orange-200";
    if (tier === "Medium") return "bg-amber-100 text-amber-800 border-amber-200";
    return "bg-emerald-100 text-emerald-800 border-emerald-200";
  };

  if (!token) {
    return (
      <div className="flex h-screen items-center justify-center bg-slate-50">
        <div className="w-96 bg-white p-8 rounded-xl shadow-lg border border-slate-200">
          <div className="flex justify-center mb-6 text-blue-600"><Shield size={56} /></div>
          <h1 className="text-2xl font-bold text-center text-slate-800 mb-6">SecureVision</h1>
          <form onSubmit={handleLogin} className="space-y-4">
            <input className="w-full p-3 border rounded bg-slate-50 text-slate-800" placeholder="Username" value={username} onChange={e => setUsername(e.target.value)} />
            <input className="w-full p-3 border rounded bg-slate-50 text-slate-800" type="password" placeholder="Password" value={password} onChange={e => setPassword(e.target.value)} />
            <button className="w-full bg-blue-600 text-white p-3 rounded font-bold hover:bg-blue-700 transition">Sign In</button>
          </form>
        </div>
      </div>
    );
  }

  const chartData = [
    { name: "Critical", count: counts.Critical || 0, color: "#ef4444" },
    { name: "High", count: counts.High || 0, color: "#f97316" },
    { name: "Medium", count: counts.Medium || 0, color: "#f59e0b" },
    { name: "Low", count: counts.Low || 0, color: "#10b981" },
  ];

  return (
    <div className="flex h-screen bg-slate-50 text-slate-800">
      {/* Sidebar */}
      <div className="w-64 bg-slate-900 text-white flex flex-col">
        <div className="p-6 flex items-center gap-3 font-bold text-xl border-b border-slate-800">
          <Shield className="text-blue-400" /> SecureVision
        </div>
        <nav className="flex-1 p-4 space-y-2">
          <button onClick={() => setView("dashboard")} className={`w-full flex items-center gap-3 p-3 rounded font-medium transition ${view === "dashboard" ? "bg-blue-600" : "hover:bg-slate-800"}`}>
            <AlertTriangle size={20} /> Dashboard
          </button>
          <button onClick={() => setView("scan")} className={`w-full flex items-center gap-3 p-3 rounded font-medium transition ${view === "scan" ? "bg-blue-600" : "hover:bg-slate-800"}`}>
            <Search size={20} /> New Scan
          </button>
          <button onClick={() => setView("import")} className={`w-full flex items-center gap-3 p-3 rounded font-medium transition ${view === "import" ? "bg-blue-600" : "hover:bg-slate-800"}`}>
            <UploadCloud size={20} /> Import CSV
          </button>
          <button onClick={() => setView("assets")} className={`w-full flex items-center gap-3 p-3 rounded font-medium transition ${view === "assets" ? "bg-blue-600" : "hover:bg-slate-800"}`}>
            <Server size={20} /> Assets
          </button>
          <button onClick={() => setView("audit")} className={`w-full flex items-center gap-3 p-3 rounded font-medium transition ${view === "audit" ? "bg-blue-600" : "hover:bg-slate-800"}`}>
            <FileText size={20} /> Audit Log
          </button>
          {role === "admin" && (
            <button onClick={() => setView("users")} className={`w-full flex items-center gap-3 p-3 rounded font-medium transition ${view === "users" ? "bg-blue-600" : "hover:bg-slate-800"}`}>
              <Users size={20} /> Users (RBAC)
            </button>
          )}
        </nav>
        <button onClick={() => setToken("")} className="p-6 border-t border-slate-800 flex items-center gap-3 hover:text-red-400 transition">
          <LogOut size={20} /> Logout
        </button>
      </div>

      {/* Main Content */}
      <div className="flex-1 overflow-auto p-8">
        {/* 1. DASHBOARD & FINDINGS VIEW */}
        {view === "dashboard" && (
          <div className="space-y-6 max-w-7xl">
            <div className="flex justify-between items-center">
              <h2 className="text-3xl font-bold text-slate-800">Vulnerability Dashboard</h2>
              <span className="text-sm text-slate-500 font-medium">320-Rule Transparent Prioritization Engine</span>
            </div>

            {/* Summary KPI Cards */}
            <div className="grid grid-cols-4 gap-6">
              {Object.entries(counts).map(([tier, count]) => (
                <div
                  key={tier}
                  onClick={() => { setFilterPriority(filterPriority === tier ? "" : tier); setPage(1); }}
                  className={`cursor-pointer bg-white p-6 rounded-xl shadow-sm border transition hover:shadow-md ${filterPriority === tier ? "ring-2 ring-blue-600 border-blue-600" : "border-slate-200"}`}
                >
                  <div className="text-slate-500 text-sm font-bold uppercase tracking-wider mb-2">{tier} (Open)</div>
                  <div className={`text-5xl font-bold ${tier === "Critical" ? "text-red-500" : tier === "High" ? "text-orange-500" : tier === "Medium" ? "text-amber-500" : "text-emerald-500"}`}>
                    {count}
                  </div>
                </div>
              ))}
            </div>

            {/* Chart */}
            <div className="bg-white p-6 rounded-xl shadow-sm border border-slate-200">
              <h3 className="text-lg font-bold mb-4 text-slate-800">Open Findings by Priority Tier</h3>
              <div className="h-56">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={chartData}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="name" />
                    <YAxis allowDecimals={false} />
                    <Tooltip />
                    <Bar dataKey="count" radius={[6, 6, 0, 0]}>
                      {chartData.map((entry, idx) => (
                        <Cell key={idx} fill={entry.color} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* Search & Filter Bar (Step 2) */}
            <div className="bg-white p-4 rounded-xl shadow-sm border border-slate-200 flex flex-wrap gap-3 items-center">
              <div className="flex items-center gap-2 text-slate-500 font-semibold text-sm mr-2">
                <Filter size={16} /> Filters:
              </div>
              <input
                className="p-2 border rounded text-sm flex-1 min-w-[200px]"
                placeholder="Search CVE ID or Asset Name..."
                value={searchQuery}
                onChange={e => { setSearchQuery(e.target.value); setPage(1); }}
              />
              <select className="p-2 border rounded text-sm" value={filterPriority} onChange={e => { setFilterPriority(e.target.value); setPage(1); }}>
                <option value="">All Priorities</option>
                <option value="Critical">Critical</option>
                <option value="High">High</option>
                <option value="Medium">Medium</option>
                <option value="Low">Low</option>
              </select>
              <select className="p-2 border rounded text-sm" value={filterStatus} onChange={e => { setFilterStatus(e.target.value); setPage(1); }}>
                <option value="">All Statuses</option>
                <option value="Open">Open</option>
                <option value="In Progress">In Progress</option>
                <option value="Resolved">Resolved</option>
              </select>
              <select className="p-2 border rounded text-sm" value={filterAssetId} onChange={e => { setFilterAssetId(e.target.value); setPage(1); }}>
                <option value="">All Assets</option>
                {assets.map((a: any) => (
                  <option key={a.id} value={a.id}>{a.name}</option>
                ))}
              </select>
              <select className="p-2 border rounded text-sm" value={sortBy} onChange={e => { setSortBy(e.target.value); setPage(1); }}>
                <option value="priority">Sort: Priority Tier</option>
                <option value="cvss">Sort: CVSS Score</option>
                <option value="epss">Sort: EPSS Likelihood</option>
                <option value="newest">Sort: Newest First</option>
              </select>
              <div className="ml-auto flex gap-2">
                <button
                  onClick={handleExportCsv}
                  disabled={exporting !== null}
                  className="rounded-md border border-slate-300 bg-white px-3 py-1.5 text-sm font-bold text-slate-700 hover:bg-slate-50 disabled:opacity-50"
                >
                  {exporting === "csv" ? "Exporting..." : "Export CSV"}
                </button>
                <button
                  onClick={handleExportPdf}
                  disabled={exporting !== null}
                  className="rounded-md bg-slate-900 px-3 py-1.5 text-sm font-bold text-white hover:bg-slate-700 disabled:opacity-50"
                >
                  {exporting === "pdf" ? "Generating..." : "Export PDF"}
                </button>
              </div>
              {(filterPriority || filterStatus || filterAssetId || searchQuery) && (
                <button
                  onClick={() => { setFilterPriority(""); setFilterStatus(""); setFilterAssetId(""); setSearchQuery(""); setPage(1); }}
                  className="text-xs font-bold text-blue-600 hover:underline px-2"
                >
                  Reset
                </button>
              )}
            </div>

            {/* Prioritized Findings Table */}
            <div className="bg-white rounded-xl shadow-sm border border-slate-200 overflow-hidden">
              <div className="p-4 border-b border-slate-200 flex justify-between items-center">
                <h3 className="font-bold text-lg">Prioritized Vulnerability Queue ({totalFindings} matching)</h3>
                <span className="text-xs text-slate-500">Click any row or Explain to inspect full 320-rule provenance</span>
              </div>
              <table className="w-full text-sm text-left">
                <thead className="bg-slate-100 text-slate-600 uppercase text-xs">
                  <tr>
                    <th className="p-3">Priority</th>
                    <th className="p-3">CVE ID</th>
                    <th className="p-3">Asset</th>
                    <th className="p-3">CVSS</th>
                    <th className="p-3">EPSS</th>
                    <th className="p-3">KEV</th>
                    <th className="p-3">Status</th>
                    <th className="p-3">Action</th>
                  </tr>
                </thead>
                <tbody>
                  {findings.map((f: any) => (
                    <tr key={f.id} className="border-t hover:bg-slate-50">
                      <td className="p-3">
                        <span className={`px-2.5 py-1 rounded-full text-xs font-bold border ${tierBadge(f.priority_tier)}`}>
                          {f.priority_tier}
                        </span>
                      </td>
                      <td className="p-3 font-mono font-bold text-blue-700 cursor-pointer hover:underline" onClick={() => openFindingDetail(f.id)}>
                        {f.cve_id}
                      </td>
                      <td className="p-3 font-medium">{f.asset_name}</td>
                      <td className="p-3 font-semibold">{Number(f.cvss_score).toFixed(1)}</td>
                      <td className="p-3">{(Number(f.epss) * 100).toFixed(1)}%</td>
                      <td className="p-3">
                        {f.in_kev ? (
                          <span className="px-2 py-0.5 rounded bg-red-600 text-white text-xs font-bold">KEV</span>
                        ) : (
                          <span className="text-slate-400 text-xs">No</span>
                        )}
                      </td>
                      <td className="p-3">
                        <select
                          value={f.status}
                          onChange={e => handleStatusChange(f.id, e.target.value)}
                          className="border rounded px-2 py-1 text-xs font-semibold bg-white"
                        >
                          <option value="Open">Open</option>
                          <option value="In Progress">In Progress</option>
                          <option value="Resolved">Resolved</option>
                        </select>
                      </td>
                      <td className="p-3">
                        <button
                          onClick={() => openFindingDetail(f.id)}
                          className="flex items-center gap-1 text-xs font-bold text-blue-600 hover:text-blue-800"
                        >
                          <Eye size={14} /> Explain
                        </button>
                      </td>
                    </tr>
                  ))}
                  {findings.length === 0 && (
                    <tr>
                      <td colSpan={8} className="p-6 text-center text-slate-500">No findings match the current filters.</td>
                    </tr>
                  )}
                </tbody>
              </table>

              {/* Pagination Controls */}
              <div className="p-4 border-t border-slate-200 flex justify-between items-center bg-slate-50">
                <span className="text-xs text-slate-600">Page {page} of {pages}</span>
                <div className="flex gap-2">
                  <button
                    disabled={page <= 1}
                    onClick={() => setPage(p => Math.max(1, p - 1))}
                    className="px-3 py-1 rounded border bg-white text-xs font-bold disabled:opacity-40"
                  >
                    Previous
                  </button>
                  <button
                    disabled={page >= pages}
                    onClick={() => setPage(p => Math.min(pages, p + 1))}
                    className="px-3 py-1 rounded border bg-white text-xs font-bold disabled:opacity-40"
                  >
                    Next
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* 2. NEW SCAN VIEW */}
        {view === "scan" && (
          <div className="max-w-3xl bg-white p-8 rounded-xl shadow-sm border border-slate-200 space-y-6">
            <div>
              <h2 className="text-2xl font-bold mb-1">Single Vulnerability Triage Scan</h2>
              <p className="text-sm text-slate-600">Evaluate a specific CVE against a registered asset using live NVD, FIRST.org EPSS, and CISA KEV threat intelligence.</p>
            </div>
            <form onSubmit={handleRunScan} className="space-y-4">
              <div>
                <label className="block text-sm font-bold mb-1">Target Asset</label>
                <select className="w-full p-3 border rounded bg-slate-50" value={scanAsset} onChange={e => setScanAsset(e.target.value)}>
                  {assets.map((a: any) => (
                    <option key={a.id} value={a.id}>
                      {a.name} ({a.exposure} | Criticality {a.criticality}/5)
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-sm font-bold mb-1">CVE Identifier</label>
                <div className="flex gap-2">
                  <input
                    className="flex-1 p-3 border rounded bg-slate-50 font-mono"
                    placeholder="e.g. CVE-2021-44228"
                    value={cveId}
                    onChange={e => setCveId(e.target.value)}
                    required
                  />
                  <button
                    type="button"
                    onClick={handleFetchIntel}
                    disabled={isFetchingIntel || !cveId.trim()}
                    className="bg-slate-800 text-white px-4 py-2 rounded font-bold hover:bg-slate-700 disabled:opacity-50"
                  >
                    {isFetchingIntel ? "Fetching..." : "Fetch Live Intel"}
                  </button>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-bold mb-1">Base CVSS Score (0 - 10)</label>
                  <input type="number" step="0.1" min="0" max="10" className="w-full p-3 border rounded bg-slate-50" value={cvss} onChange={e => setCvss(e.target.value)} required />
                </div>
                <div>
                  <label className="block text-sm font-bold mb-1">EPSS Probability (0.0 - 1.0)</label>
                  <input type="number" step="0.0001" min="0" max="1" className="w-full p-3 border rounded bg-slate-50" value={epss} onChange={e => setEpss(e.target.value)} required />
                </div>
              </div>

              <label className="flex items-center gap-2 font-semibold text-sm cursor-pointer">
                <input type="checkbox" checked={inKev} onChange={e => setInKev(e.target.checked)} className="w-4 h-4" />
                Listed in CISA Known Exploited Vulnerabilities (KEV) Catalog
              </label>

              {scanError && <p className="text-red-600 text-sm font-bold">{scanError}</p>}

              <button type="submit" className="w-full bg-blue-600 text-white p-3 rounded font-bold hover:bg-blue-700 transition">
                Evaluate with 320-Rule Matrix
              </button>
            </form>

            {scanResult && (
              <div className="p-5 rounded-xl border bg-slate-50 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-slate-700">Assigned Priority Tier:</span>
                  <span className={`px-3 py-1 rounded-full text-sm font-bold border ${tierBadge(scanResult.priority_tier)}`}>
                    {scanResult.priority_tier}
                  </span>
                </div>
                <p className="text-sm text-slate-700"><strong>Rule Explanation:</strong> {scanResult.explanation}</p>
              </div>
            )}
          </div>
        )}

        {/* 3. IMPORT CSV VIEW (Step 1) */}
        {view === "import" && (
          <div className="max-w-5xl bg-white p-8 rounded-xl shadow-sm border border-slate-200">
            <h2 className="text-2xl font-bold mb-2">Import Findings (CSV)</h2>
            <p className="text-sm text-slate-600 mb-6">Required columns: asset_name, cve_id, date_found (YYYY-MM-DD).</p>
            <input
              type="file"
              accept=".csv"
              onChange={(e) => {
                setImportFile(e.target.files?.[0] ?? null);
                setImportRows([]);
                setImportSummary(null);
                setImportResult(null);
              }}
              className="mb-4 block w-full text-sm text-slate-500 file:mr-4 file:py-2 file:px-4 file:rounded border file:font-semibold file:bg-blue-50 file:text-blue-700 hover:file:bg-blue-100"
            />
            <div className="flex gap-2 mb-4">
              <button
                disabled={!importFile || importBusy}
                className="rounded bg-slate-800 px-4 py-2 text-white disabled:opacity-50 font-bold"
                onClick={() => runImport("/imports/preview", (d: any) => { setImportRows(d.rows); setImportSummary(d.summary); setImportResult(null); })}
              >
                Preview
              </button>
              <button
                disabled={!importSummary || importSummary.ok === 0 || importBusy}
                className="rounded bg-emerald-600 px-4 py-2 text-white disabled:opacity-50 font-bold"
                onClick={() => runImport("/imports/commit", (d: any) => setImportResult(d))}
              >
                Import {importSummary ? importSummary.ok : 0} valid rows
              </button>
            </div>
            {importError && <p className="text-red-700 font-bold mb-4">{importError}</p>}
            {importSummary && !importResult && (
              <p className="mb-4 font-medium text-slate-700">
                Total {importSummary.total}: {importSummary.ok} valid, {importSummary.error} errors, {importSummary.duplicate} duplicates.
              </p>
            )}
            {importResult && (
              <div className="rounded border border-emerald-200 bg-emerald-50 p-4 mb-4 text-emerald-900 font-medium">
                Imported {importResult.imported}, skipped {importResult.skipped}.{" "}
                {importResult.skipped > 0 && (
                  <button className="underline font-bold" onClick={downloadProblems}>
                    Download the problems as CSV
                  </button>
                )}
              </div>
            )}
            {importRows.length > 0 && (
              <div className="max-h-96 overflow-auto rounded border border-slate-200">
                <table className="w-full text-sm text-left">
                  <thead className="sticky top-0 bg-slate-100">
                    <tr>
                      <th className="p-3">Line</th>
                      <th className="p-3">Asset</th>
                      <th className="p-3">CVE</th>
                      <th className="p-3">Date</th>
                      <th className="p-3">Result</th>
                      <th className="p-3">Reason</th>
                    </tr>
                  </thead>
                  <tbody>
                    {importRows.map((r: any) => (
                      <tr key={r.line} className="border-t hover:bg-slate-50">
                        <td className="p-3">{r.line}</td>
                        <td className="p-3">{r.asset_name}</td>
                        <td className="p-3">{r.cve_id}</td>
                        <td className="p-3">{r.date_found}</td>
                        <td className="p-3">
                          <span className={`rounded px-2 py-1 text-xs font-bold ${r.status === "ok" ? "bg-green-100 text-green-800" : r.status === "error" ? "bg-red-100 text-red-800" : "bg-amber-100 text-amber-800"}`}>
                            {r.status}
                          </span>
                        </td>
                        <td className="p-3">{r.reason}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {/* 4. ASSETS VIEW */}
        {view === "assets" && (
          <div className="max-w-5xl space-y-6">
            <div className="bg-white p-6 rounded-xl shadow-sm border border-slate-200">
              <h2 className="text-xl font-bold mb-4 flex items-center gap-2"><PlusCircle size={20} className="text-blue-600" /> Register New Asset</h2>
              <form onSubmit={handleCreateAsset} className="grid grid-cols-4 gap-4 items-end">
                <div className="col-span-2">
                  <label className="block text-xs font-bold uppercase text-slate-500 mb-1">Asset Name</label>
                  <input className="w-full p-2.5 border rounded bg-slate-50" placeholder="e.g. Core Banking API" value={newAssetName} onChange={e => setNewAssetName(e.target.value)} required />
                </div>
                <div>
                  <label className="block text-xs font-bold uppercase text-slate-500 mb-1">Network Exposure</label>
                  <select className="w-full p-2.5 border rounded bg-slate-50" value={newAssetExposure} onChange={e => setNewAssetExposure(e.target.value)}>
                    <option value="Internet">Internet</option>
                    <option value="Internal">Internal</option>
                  </select>
                </div>
                <div>
                  <label className="block text-xs font-bold uppercase text-slate-500 mb-1">Criticality (1-5)</label>
                  <div className="flex gap-2">
                    <input type="number" min="1" max="5" className="w-20 p-2.5 border rounded bg-slate-50" value={newAssetCrit} onChange={e => setNewAssetCrit(Number(e.target.value))} required />
                    <button type="submit" className="flex-1 bg-blue-600 text-white px-4 py-2.5 rounded font-bold hover:bg-blue-700">Add</button>
                  </div>
                </div>
              </form>
              {assetMsg && <p className="mt-3 text-sm font-semibold text-emerald-700 flex items-center gap-1"><CheckCircle2 size={16} /> {assetMsg}</p>}
            </div>

            <div className="bg-white rounded-xl shadow-sm border border-slate-200 overflow-hidden">
              <div className="p-4 border-b border-slate-200 font-bold text-lg">Registered Organization Assets ({assets.length})</div>
              <table className="w-full text-sm text-left">
                <thead className="bg-slate-100 text-slate-600 uppercase text-xs">
                  <tr>
                    <th className="p-3">ID</th>
                    <th className="p-3">Asset Name</th>
                    <th className="p-3">Network Exposure</th>
                    <th className="p-3">Business Criticality</th>
                  </tr>
                </thead>
                <tbody>
                  {assets.map((a: any) => (
                    <tr key={a.id} className="border-t hover:bg-slate-50">
                      <td className="p-3 font-mono text-slate-500">#{a.id}</td>
                      <td className="p-3 font-bold">{a.name}</td>
                      <td className="p-3">
                        <span className={`px-2 py-1 rounded text-xs font-bold ${a.exposure.toLowerCase() === "internet" ? "bg-purple-100 text-purple-800" : "bg-slate-100 text-slate-700"}`}>
                          {a.exposure}
                        </span>
                      </td>
                      <td className="p-3 font-semibold">Tier {a.criticality} / 5</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* 5. AUDIT LOG VIEW */}
        {view === "audit" && (
          <div className="max-w-6xl bg-white rounded-xl shadow-sm border border-slate-200 overflow-hidden">
            <div className="p-5 border-b border-slate-200 flex justify-between items-center">
              <div>
                <h2 className="text-xl font-bold">Immutable Security Audit Trail</h2>
                <p className="text-xs text-slate-500">Tracks every scan, CSV batch import, asset registration, and status change.</p>
              </div>
            </div>
            <table className="w-full text-sm text-left">
              <thead className="bg-slate-100 text-slate-600 uppercase text-xs">
                <tr>
                  <th className="p-3">ID</th>
                  <th className="p-3">Timestamp</th>
                  <th className="p-3">User</th>
                  <th className="p-3">Action</th>
                  <th className="p-3">Details</th>
                </tr>
              </thead>
              <tbody>
                {auditLogs.map((l: any) => (
                  <tr key={l.id} className="border-t hover:bg-slate-50">
                    <td className="p-3 font-mono text-xs text-slate-500">#{l.id}</td>
                    <td className="p-3 text-xs text-slate-500">{l.timestamp ? new Date(l.timestamp).toLocaleString() : "Just now"}</td>
                    <td className="p-3 font-bold">{l.user}</td>
                    <td className="p-3">
                      <span className="px-2 py-1 rounded bg-slate-800 text-white text-xs font-mono font-bold">{l.action}</span>
                    </td>
                    <td className="p-3 font-mono text-xs text-slate-700 break-all">{l.details}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* 6. USERS RBAC VIEW (Step 4) */}
        {view === "users" && role === "admin" && (
          <div className="max-w-5xl space-y-6">
            <div className="bg-white p-6 rounded-xl shadow-sm border border-slate-200">
              <h2 className="text-xl font-bold mb-4 flex items-center gap-2"><Users size={20} className="text-blue-600" /> Create User Account (RBAC)</h2>
              <form onSubmit={handleCreateUser} className="grid grid-cols-4 gap-4 items-end">
                <div>
                  <label className="block text-xs font-bold uppercase text-slate-500 mb-1">Username</label>
                  <input className="w-full p-2.5 border rounded bg-slate-50" placeholder="e.g. analyst_jane" value={newUsername} onChange={e => setNewUsername(e.target.value)} required />
                </div>
                <div>
                  <label className="block text-xs font-bold uppercase text-slate-500 mb-1">Password (min 8 chars)</label>
                  <input type="password" className="w-full p-2.5 border rounded bg-slate-50" placeholder="••••••••" value={newUserPassword} onChange={e => setNewUserPassword(e.target.value)} required />
                </div>
                <div>
                  <label className="block text-xs font-bold uppercase text-slate-500 mb-1">Role</label>
                  <select className="w-full p-2.5 border rounded bg-slate-50" value={newUserRole} onChange={e => setNewUserRole(e.target.value)}>
                    <option value="analyst">Analyst (Scan, Import, Triage)</option>
                    <option value="viewer">Viewer (Read & Export Only)</option>
                    <option value="admin">Admin (Full Control)</option>
                  </select>
                </div>
                <div>
                  <button type="submit" className="w-full bg-blue-600 text-white px-4 py-2.5 rounded font-bold hover:bg-blue-700">Create User</button>
                </div>
              </form>
              {userMsg && <p className="mt-3 text-sm font-semibold text-emerald-700">{userMsg}</p>}
              {userErr && <p className="mt-3 text-sm font-semibold text-red-600">{userErr}</p>}
            </div>

            <div className="bg-white rounded-xl shadow-sm border border-slate-200 overflow-hidden">
              <div className="p-4 border-b border-slate-200 font-bold text-lg">System Users & Roles ({usersList.length})</div>
              <table className="w-full text-sm text-left">
                <thead className="bg-slate-100 text-slate-600 uppercase text-xs">
                  <tr>
                    <th className="p-3">ID</th>
                    <th className="p-3">Username</th>
                    <th className="p-3">Assigned Role</th>
                    <th className="p-3">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {usersList.map((u: any) => (
                    <tr key={u.id} className="border-t hover:bg-slate-50">
                      <td className="p-3 font-mono text-slate-500">#{u.id}</td>
                      <td className="p-3 font-bold">{u.username}</td>
                      <td className="p-3">
                        <select
                          value={u.role}
                          onChange={e => handleRoleChange(u.id, e.target.value)}
                          className="border rounded px-2.5 py-1 text-xs font-bold bg-white"
                        >
                          <option value="admin">admin</option>
                          <option value="analyst">analyst</option>
                          <option value="viewer">viewer</option>
                        </select>
                      </td>
                      <td className="p-3">
                        <button
                          onClick={() => handleDeleteUser(u.id)}
                          className="flex items-center gap-1 text-xs font-bold text-red-600 hover:text-red-800"
                        >
                          <Trash2 size={14} /> Delete
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* FINDING DETAIL MODAL (Step 2 Explainability Drawer) */}
        {(selectedFinding || detailLoading) && (
          <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
            <div className="bg-white rounded-xl shadow-2xl max-w-2xl w-full p-6 space-y-4 max-h-[90vh] overflow-auto">
              {detailLoading || !selectedFinding ? (
                <p className="text-center py-8 font-bold text-slate-600">Loading finding provenance...</p>
              ) : (
                <>
                  <div className="flex justify-between items-start border-b pb-3">
                    <div>
                      <div className="flex items-center gap-3">
                        <h3 className="text-2xl font-bold font-mono text-blue-700">{selectedFinding.cve_id}</h3>
                        <span className={`px-3 py-1 rounded-full text-xs font-bold border ${tierBadge(selectedFinding.priority_tier)}`}>
                          {selectedFinding.priority_tier}
                        </span>
                      </div>
                      <p className="text-xs text-slate-500 mt-1">Finding #{selectedFinding.id} | Date Found: {selectedFinding.date_found}</p>
                    </div>
                    <button onClick={() => setSelectedFinding(null)} className="text-slate-400 hover:text-slate-700">
                      <X size={22} />
                    </button>
                  </div>

                  {/* Asset Context & Threat Signals */}
                  <div className="grid grid-cols-2 gap-4">
                    <div className="p-4 rounded-lg bg-slate-50 border">
                      <div className="text-xs font-bold uppercase text-slate-500 mb-2">Asset Context</div>
                      <p className="text-sm"><strong>Name:</strong> {selectedFinding.asset?.name}</p>
                      <p className="text-sm"><strong>Exposure:</strong> {selectedFinding.asset?.exposure}</p>
                      <p className="text-sm"><strong>Criticality:</strong> {selectedFinding.asset?.criticality} / 5</p>
                    </div>
                    <div className="p-4 rounded-lg bg-slate-50 border">
                      <div className="text-xs font-bold uppercase text-slate-500 mb-2">Threat Intel Signals</div>
                      <p className="text-sm"><strong>NVD CVSS Base:</strong> {Number(selectedFinding.cvss_score).toFixed(1)} / 10</p>
                      <p className="text-sm"><strong>FIRST.org EPSS:</strong> {(Number(selectedFinding.likelihood) * 100).toFixed(2)}%</p>
                      <p className="text-sm"><strong>CISA KEV Active Exploit:</strong> {selectedFinding.in_kev ? "YES (In KEV)" : "No"}</p>
                    </div>
                  </div>

                  {/* Matched Rule Explanation */}
                  <div className="p-4 rounded-lg bg-blue-50 border border-blue-200">
                    <div className="text-xs font-bold uppercase text-blue-700 mb-1">320-Rule Matrix Decision Explanation</div>
                    <p className="text-sm font-medium text-slate-800">{selectedFinding.explanation}</p>
                  </div>

                  {/* Score History */}
                  <div>
                    <div className="text-xs font-bold uppercase text-slate-500 mb-2">Score Provenance History</div>
                    <div className="border rounded divide-y text-xs">
                      {selectedFinding.score_history?.map((s: any) => (
                        <div key={s.id} className="p-2.5 flex justify-between items-center">
                          <span><strong>Tier:</strong> {s.priority_tier} (EPSS {(Number(s.likelihood) * 100).toFixed(1)}%)</span>
                          <span className="font-mono text-slate-500">Source: {s.provenance?.source || "Engine"}</span>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Audit History for this Finding */}
                  {selectedFinding.audit_trail?.length > 0 && (
                    <div>
                      <div className="text-xs font-bold uppercase text-slate-500 mb-2">Related Audit Trail</div>
                      <div className="border rounded divide-y text-xs max-h-36 overflow-auto">
                        {selectedFinding.audit_trail.map((a: any) => (
                          <div key={a.id} className="p-2 flex justify-between">
                            <span><strong>{a.action}</strong> by {a.user}: {a.details}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}