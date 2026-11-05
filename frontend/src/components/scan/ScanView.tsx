"use client";
import type { SecureAppViewProps } from "@/types/views";

export function ScanView(props: SecureAppViewProps) {
  const {
    activeTab, tabAnimKey, surfaceCard, headingColor, mutedText, role,
    darkMode, handleCreateScan, scanCve, setScanCve, scanAssetId,
    setScanAssetId, assets, scanCvss, setScanCvss, scanEpss,
    setScanEpss, scanKev, setScanKev,
  } = props;
  return (activeTab === "scan" && (role === "admin" || role === "analyst") && (
          <div key={`scan-${tabAnimKey}`} className={`rounded-3xl p-6 md:p-8 border max-w-2xl sv-tab-transition ${surfaceCard}`}>
            <h2 className={`text-2xl font-extrabold mb-1 ${headingColor}`}>
              Evaluate New Vulnerability Scan
            </h2>
            <p className={`text-xs mb-6 ${mutedText}`}>
              Submit vulnerability inputs to the backend scoring engine. Exposure and criticality come from the selected asset.
            </p>
            <form onSubmit={handleCreateScan} noValidate className="space-y-4">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className={`block text-xs font-bold mb-1 ${headingColor}`}>CVE Identifier</label>
                  <input
                    type="text"
                    value={scanCve}
                    onChange={(e) => setScanCve(e.target.value)}
                    className={`w-full px-4 py-2.5 rounded-xl border text-sm focus:outline-none focus:border-[#00E5C4] ${darkMode ? "bg-[#15082E] border-white/15 text-white" : "bg-white border-slate-200"}`}
                    required
                  />
                </div>
                <div>
                  <label className={`block text-xs font-bold mb-1 ${headingColor}`}>Asset</label>
                  <select
                    value={scanAssetId}
                    onChange={(e) => setScanAssetId(e.target.value)}
                    className={`w-full px-4 py-2.5 rounded-xl border text-sm focus:outline-none focus:border-[#00E5C4] ${darkMode ? "bg-[#15082E] border-white/15 text-white" : "bg-white border-slate-200"}`}
                    required
                  >
                    <option value="">Select an asset</option>
                    {assets.map((asset) => (
                      <option key={asset.id} value={asset.id}>
                        {asset.name} ({asset.exposure}, criticality {asset.criticality})
                      </option>
                    ))}
                  </select>
                </div>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                <div>
                  <label className={`block text-xs font-bold mb-1 ${headingColor}`}>CVSS (0-10)</label>
                  <input
                    type="number"
                    step="0.1"
                    min="0"
                    max="10"
                    value={scanCvss}
                    onChange={(e) => setScanCvss(e.target.value)}
                    className={`w-full px-3 py-2.5 rounded-xl border text-sm ${darkMode ? "bg-[#15082E] border-white/15 text-white" : "bg-white border-slate-200"}`}
                  />
                </div>
                <div>
                  <label className={`block text-xs font-bold mb-1 ${headingColor}`}>EPSS Percentile (0-1)</label>
                  <input
                    type="number"
                    step="0.000001"
                    min="0"
                    max="1"
                    value={scanEpss}
                    onChange={(e) => setScanEpss(e.target.value)}
                    className={`w-full px-3 py-2.5 rounded-xl border text-sm ${darkMode ? "bg-[#15082E] border-white/15 text-white" : "bg-white border-slate-200"}`}
                  />
                </div>
                <div>
                  <label className={`block text-xs font-bold mb-1 ${headingColor}`}>CISA KEV</label>
                  <select
                    value={scanKev ? "true" : "false"}
                    onChange={(e) => setScanKev(e.target.value === "true")}
                    className={`w-full px-3 py-2.5 rounded-xl border text-sm ${darkMode ? "bg-[#15082E] border-white/15 text-white" : "bg-white border-slate-200"}`}
                  >
                    <option value="false">No</option>
                    <option value="true">Yes</option>
                  </select>
                </div>
              </div>
              <button
                type="submit"
                className="px-6 py-3 rounded-full bg-gradient-to-r from-[#8121D7] to-[#00B89E] text-white font-bold text-xs shadow-md hover:opacity-95 hover:scale-105 transition-all cursor-pointer"
              >
                Score with backend
              </button>
            </form>
          </div>
        ));
}
