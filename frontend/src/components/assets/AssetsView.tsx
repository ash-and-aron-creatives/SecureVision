"use client";
import type { SecureAppViewProps } from "@/types/views";

export function AssetsView(props: SecureAppViewProps) {
  const {
    activeTab, tabAnimKey, surfaceCard, headingColor, mutedText,
    darkMode, subSurfaceCard, assets, handleCreateAsset, assetHost, role,
    setAssetHost, assetExposure, setAssetExposure, assetCrit, setAssetCrit,
  } = props;
  return (activeTab === "assets" && (
          <div key={`assets-${tabAnimKey}`} className={`rounded-3xl p-6 md:p-8 border space-y-6 sv-tab-transition ${surfaceCard}`}>
            <h2 className={`text-2xl font-extrabold ${headingColor}`}>
              Enterprise Asset Inventory
            </h2>
            {(role === "admin" || role === "analyst") && (
              <form onSubmit={handleCreateAsset} className={`grid grid-cols-1 sm:grid-cols-5 gap-3 p-4 rounded-2xl border ${subSurfaceCard}`}>
                <input
                  type="text"
                  placeholder="Hostname (e.g. db-prod-01)"
                  value={assetHost}
                  onChange={(e) => setAssetHost(e.target.value)}
                  className={`px-3.5 py-2 rounded-xl border text-sm ${darkMode ? "bg-[#15082E] border-white/15 text-white" : "bg-white border-slate-200"}`}
                  required
                />
                <select
                  value={assetExposure}
                  onChange={(e) => setAssetExposure(e.target.value)}
                  className={`px-3.5 py-2 rounded-xl border text-sm ${darkMode ? "bg-[#15082E] border-white/15 text-white" : "bg-white border-slate-200"}`}
                >
                  <option value="internet">Internet-Facing</option>
                  <option value="internal">Internal</option>
                </select>
                <select
                  value={assetCrit}
                  onChange={(e) => setAssetCrit(e.target.value)}
                  className={`px-3.5 py-2 rounded-xl border text-sm ${darkMode ? "bg-[#15082E] border-white/15 text-white" : "bg-white border-slate-200"}`}
                >
                  <option value="5">Criticality Tier 5</option>
                  <option value="4">Criticality Tier 4</option>
                  <option value="3">Criticality Tier 3</option>
                </select>
                <button
                  type="submit"
                  className="px-4 py-2 rounded-xl bg-gradient-to-r from-[#8121D7] to-[#1ABDD6] text-white font-bold text-xs cursor-pointer"
                >
                  + Register Asset
                </button>
              </form>
            )}

            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-4">
              {assets.map((a, idx) => (
                <div
                  key={a.id}
                  style={{ animationDelay: `${idx * 0.06}s` }}
                  className={`sv-card-pop p-5 rounded-2xl border hover:-translate-y-1 transition-all flex items-center justify-between ${subSurfaceCard}`}
                >
                  <div>
                    <p className={`font-bold text-sm ${headingColor}`}>{a.name}</p>
                    <p className={`text-xs ${mutedText}`}>{a.exposure}</p>
                    {a.needs_review && (
                      <p className="mt-1 text-[10px] font-bold uppercase tracking-wide text-amber-600 dark:text-amber-300">
                        Needs review
                      </p>
                    )}
                  </div>
                  <span className="px-2.5 py-1 rounded-full text-xs font-extrabold bg-[#8121D7]/15 text-[#8121D7] dark:text-[#00E5C4]">
                    Tier {a.criticality}
                  </span>
                </div>
              ))}
            </div>
          </div>
        ));
}
