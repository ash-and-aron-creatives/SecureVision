"use client";
import type { SecureAppViewProps } from "@/types/views";

export function AssetsView(props: SecureAppViewProps) {
  const {
    activeTab, tabAnimKey, surfaceCard, headingColor, mutedText,
    darkMode, subSurfaceCard, assets, handleSaveAsset, handleEditAsset,
    handleCancelAssetEdit, handleDeleteAsset, assetHost, role, setAssetHost,
    assetType, setAssetType, assetAddress, setAssetAddress, assetOwner,
    setAssetOwner, assetEnvironment, setAssetEnvironment, assetExposure,
    setAssetExposure, assetCrit, setAssetCrit, editingAssetId,
  } = props;
  return (activeTab === "assets" && (
          <div key={`assets-${tabAnimKey}`} className={`rounded-3xl p-6 md:p-8 border space-y-6 sv-tab-transition ${surfaceCard}`}>
            <h2 className={`text-2xl font-extrabold ${headingColor}`}>
              Enterprise Asset Inventory
            </h2>
            {(role === "admin" || role === "analyst") && (
              <form onSubmit={handleSaveAsset} className={`grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 p-4 rounded-2xl border ${subSurfaceCard}`}>
                <input
                  type="text"
                  placeholder="Asset name"
                  value={assetHost}
                  onChange={(e) => setAssetHost(e.target.value)}
                  className={`px-3.5 py-2 rounded-xl border text-sm ${darkMode ? "bg-[#15082E] border-white/15 text-white" : "bg-white border-slate-200"}`}
                  required
                />
                <select
                  value={assetType}
                  onChange={(e) => setAssetType(e.target.value)}
                  className={`px-3.5 py-2 rounded-xl border text-sm ${darkMode ? "bg-[#15082E] border-white/15 text-white" : "bg-white border-slate-200"}`}
                >
                  {["Server", "Workstation", "Network", "Cloud", "Application", "Other"].map((type) => (
                    <option key={type} value={type}>{type}</option>
                  ))}
                </select>
                <input
                  type="text"
                  placeholder="IP address or hostname"
                  value={assetAddress}
                  onChange={(e) => setAssetAddress(e.target.value)}
                  className={`px-3.5 py-2 rounded-xl border text-sm ${darkMode ? "bg-[#15082E] border-white/15 text-white" : "bg-white border-slate-200"}`}
                />
                <input
                  type="text"
                  placeholder="Owner"
                  value={assetOwner}
                  onChange={(e) => setAssetOwner(e.target.value)}
                  className={`px-3.5 py-2 rounded-xl border text-sm ${darkMode ? "bg-[#15082E] border-white/15 text-white" : "bg-white border-slate-200"}`}
                />
                <select
                  value={assetEnvironment}
                  onChange={(e) => setAssetEnvironment(e.target.value)}
                  className={`px-3.5 py-2 rounded-xl border text-sm ${darkMode ? "bg-[#15082E] border-white/15 text-white" : "bg-white border-slate-200"}`}
                >
                  {["Production", "Staging", "Development", "Testing", "Other", "Unknown"].map((environment) => (
                    <option key={environment} value={environment}>{environment}</option>
                  ))}
                </select>
                <select
                  value={assetExposure}
                  onChange={(e) => setAssetExposure(e.target.value)}
                  className={`px-3.5 py-2 rounded-xl border text-sm ${darkMode ? "bg-[#15082E] border-white/15 text-white" : "bg-white border-slate-200"}`}
                >
                  <option value="Internet">Internet-Facing</option>
                  <option value="Internal">Internal</option>
                </select>
                <select
                  value={assetCrit}
                  onChange={(e) => setAssetCrit(e.target.value)}
                  className={`px-3.5 py-2 rounded-xl border text-sm ${darkMode ? "bg-[#15082E] border-white/15 text-white" : "bg-white border-slate-200"}`}
                >
                  <option value="5">Criticality Tier 5</option>
                  <option value="4">Criticality Tier 4</option>
                  <option value="3">Criticality Tier 3</option>
                  <option value="2">Criticality Tier 2</option>
                  <option value="1">Criticality Tier 1</option>
                </select>
                <button
                  type="submit"
                  className="px-4 py-2 rounded-xl bg-gradient-to-r from-[#8121D7] to-[#1ABDD6] text-white font-bold text-xs cursor-pointer"
                >
                  {editingAssetId === null ? "+ Register Asset" : "Save Asset"}
                </button>
                {editingAssetId !== null && (
                  <button
                    type="button"
                    onClick={handleCancelAssetEdit}
                    className={`px-4 py-2 rounded-xl border font-bold text-xs cursor-pointer ${darkMode ? "border-white/15 text-white" : "border-slate-200 text-slate-600"}`}
                  >
                    Cancel
                  </button>
                )}
              </form>
            )}

            <div className="overflow-x-auto rounded-2xl border border-slate-200/70 dark:border-white/10">
              <table className="w-full min-w-[900px] text-left text-xs">
                <thead className={darkMode ? "bg-white/5 text-white/60" : "bg-slate-50 text-slate-500"}>
                  <tr>
                    {["Name", "Type", "IP / Domain", "Owner", "Environment", "Exposure", "Criticality", "Actions"].map((column) => (
                      <th key={column} className="px-4 py-3 font-bold uppercase tracking-wide">{column}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {assets.map((asset) => (
                    <tr key={asset.id} className={`border-t ${darkMode ? "border-white/10" : "border-slate-100"}`}>
                      <td className={`px-4 py-3 font-bold ${headingColor}`}>
                        {asset.name}
                        {asset.needs_review && <span className="ml-2 text-[10px] font-bold text-amber-500">Needs review</span>}
                      </td>
                      <td className={`px-4 py-3 ${mutedText}`}>{asset.type}</td>
                      <td className={`px-4 py-3 ${mutedText}`}>{asset.ip_or_domain || "—"}</td>
                      <td className={`px-4 py-3 ${mutedText}`}>{asset.owner || "—"}</td>
                      <td className={`px-4 py-3 ${mutedText}`}>{asset.environment}</td>
                      <td className={`px-4 py-3 ${mutedText}`}>{asset.exposure}</td>
                      <td className={`px-4 py-3 ${mutedText}`}>Tier {asset.criticality}</td>
                      <td className="px-4 py-3">
                        {(role === "admin" || role === "analyst") && (
                          <div className="flex items-center gap-2">
                            <button type="button" onClick={() => handleEditAsset(asset)} className="font-bold text-[#8121D7] dark:text-[#00E5C4] cursor-pointer">Edit</button>
                            <button type="button" onClick={() => void handleDeleteAsset(asset)} className="font-bold text-rose-500 cursor-pointer">Delete</button>
                          </div>
                        )}
                      </td>
                    </tr>
                  ))}
                  {assets.length === 0 && (
                    <tr><td colSpan={8} className={`px-4 py-6 text-center ${mutedText}`}>No assets registered.</td></tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        ));
}
