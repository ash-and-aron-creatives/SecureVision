"use client";
import type { SecureAppViewProps } from "@/types/views";

export function ScanView(props: SecureAppViewProps) {
  const {
    activeTab, tabAnimKey, surfaceCard, headingColor, mutedText, role,
    darkMode, handleCreateScan, handleLookupIntel, intelMessage, isLookingUpIntel,
    scanCve, setScanCve, scanAssetId,
    setScanAssetId, assets, scanCvss, setScanCvss, scanEpss,
    setScanEpss, scanKev, setScanKev, scanResult,
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
                  <button
                    type="button"
                    onClick={handleLookupIntel}
                    disabled={isLookingUpIntel}
                    className="mt-2 text-xs font-semibold text-[#00B89E] hover:underline disabled:opacity-50"
                  >
                    {isLookingUpIntel ? "Looking up..." : "Look up CVE scores"}
                  </button>
                  {intelMessage && (
                    <p className={`mt-2 text-xs ${mutedText}`} role="status">{intelMessage}</p>
                  )}
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
                <p className={`sm:col-span-3 text-xs ${mutedText}`}>
                  Leave either score blank to retrieve it during scoring. If a required score is unavailable, the scan is rejected rather than scored as zero.
                </p>
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
            {scanResult && (
              <section className="mt-6 rounded-2xl border border-[#00E5C4]/25 bg-[#00E5C4]/5 p-5">
                <h3 className="text-sm font-extrabold text-[#00E5C4]">Scan result evidence</h3>
                <dl className="mt-4 grid grid-cols-2 gap-4 text-xs">
                  <div>
                    <dt className="text-white/50">Final priority</dt>
                    <dd className="font-bold">{scanResult.final_priority}</dd>
                  </div>
                  <div>
                    <dt className="text-white/50">Priority source</dt>
                    <dd>{scanResult.priority_source}</dd>
                  </div>
                  <div>
                    <dt className="text-white/50">ML likelihood</dt>
                    <dd>{scanResult.ml_likelihood === null
                      ? "Unavailable"
                      : `${(scanResult.ml_likelihood * 100).toFixed(2)}%`}</dd>
                  </div>
                  <div>
                    <dt className="text-white/50">ML tier</dt>
                    <dd>{scanResult.ml_priority ?? "Unavailable"}</dd>
                  </div>
                  <div>
                    <dt className="text-white/50">Rule tier (cross-check)</dt>
                    <dd>{scanResult.rule_priority_tier}</dd>
                  </div>
                  <div>
                    <dt className="text-white/50">Recommended action</dt>
                    <dd>{scanResult.recommended_action}</dd>
                  </div>
                </dl>
                <div className="mt-4">
                  <p className="text-xs font-bold text-white/70">Top 3 model factors</p>
                  {scanResult.ml_top_reasons?.length ? (
                    <ol className="mt-2 list-decimal list-inside space-y-1 text-xs text-white/80">
                      {scanResult.ml_top_reasons.slice(0, 3).map((reason) => (
                        <li key={reason}>{reason}</li>
                      ))}
                    </ol>
                  ) : (
                    <p className="mt-2 text-xs text-white/55">
                      {scanResult.ml_unavailable_reason ?? "Unavailable"}
                    </p>
                  )}
                </div>
                <p className="mt-4 border-t border-white/10 pt-3 text-[11px] text-white/55">
                  Experimental model. It did not beat CVSS on the frozen 2026 test; see Model Results.
                </p>
              </section>
            )}
          </div>
        ));
}
