"use client";
import type { SecureAppViewProps } from "@/types/views";

export function FindingsView(props: SecureAppViewProps) {
  const {
    activeTab, tabAnimKey, surfaceCard, headingColor, mutedText,
    darkMode, getTier, setTierFilter, tierFilter, exportPriorityCsv,
    filteredFindings, toggleFindingStatus, setSelectedFinding, role,
  } = props;
  return (activeTab === "queue" && (
          <div key={`queue-${tabAnimKey}`} className={`rounded-3xl p-4 sm:p-6 md:p-8 border sv-tab-transition ${surfaceCard}`}>
            <div className="flex flex-wrap items-center justify-between gap-4 mb-6">
              <div>
                <h2 className={`text-2xl font-extrabold ${headingColor}`}>
                  Priority Queue
                </h2>
                <p className={`text-xs ${mutedText}`}>
                  Click a row to view the backend explanation
                </p>
              </div>
              <div className="flex flex-wrap items-center gap-2">
                {["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"].map((tier) => (
                  <button
                    key={tier}
                    onClick={() => setTierFilter(tier)}
                    className={`px-3.5 py-1.5 rounded-full text-xs font-bold transition-all cursor-pointer ${
                      tierFilter === tier
                        ? "bg-gradient-to-r from-[#8121D7] to-[#1ABDD6] text-white shadow-sm scale-105"
                        : darkMode
                        ? "bg-white/10 text-white/70 hover:bg-white/20"
                        : "bg-slate-100 text-slate-600 hover:bg-slate-200"
                    }`}
                  >
                    {tier}
                  </button>
                ))}
                <button
                  onClick={exportPriorityCsv}
                  className="ml-1 sm:ml-2 px-4 py-1.5 rounded-full text-xs font-bold bg-[#00E5C4]/15 text-[#00B89E] border border-[#00E5C4]/30 hover:bg-[#00E5C4] hover:text-[#120524] transition-all cursor-pointer"
                >
                  ↓ Export CSV
                </button>
              </div>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className={`border-b text-[11px] font-bold uppercase tracking-wider ${darkMode ? "border-white/10 text-white/50" : "border-slate-200 text-slate-400"}`}>
                    <th className="py-3 px-4">CVE ID</th>
                    <th className="py-3 px-4">Host / Asset</th>
                    <th className="py-3 px-4">CVSS</th>
                    <th className="py-3 px-4">Score</th>
                    <th className="py-3 px-4">Final priority</th>
                    <th className="py-3 px-4">Action</th>
                  </tr>
                </thead>
                <tbody className={`divide-y text-sm ${darkMode ? "divide-white/10" : "divide-slate-100"}`}>
                  {filteredFindings.map((f, idx) => {
                    const tier = getTier(f);
                    const isResolved = (f.status || "OPEN").toUpperCase() === "RESOLVED";
                    return (
                      <tr
                        key={f.id}
                        onClick={() => setSelectedFinding(f)}
                        style={{ animationDelay: `${Math.min(idx * 0.03, 0.35)}s` }}
                        className={`sv-card-pop transition-colors cursor-pointer ${darkMode ? "hover:bg-white/5" : "hover:bg-slate-50/80"}`}
                      >
                        <td className={`py-3.5 px-4 font-bold ${headingColor}`}>
                          {f.cve_id}
                          <div className={`text-[11px] font-normal ${mutedText}`}>{f.explanation.summary}</div>
                        </td>
                        <td className="py-3.5 px-4 font-medium">
                          {f.asset_name}
                        </td>
                        <td className="py-3.5 px-4 font-bold">
                          {f.cvss_score}
                        </td>
                        <td className="py-3.5 px-4 font-extrabold text-[#00B89E]">
                          {f.score}/4
                        </td>
                        <td className="py-3.5 px-4">
                          <span
                            className={`text-[11px] font-extrabold px-2.5 py-1 rounded-full text-white ${
                              tier === "CRITICAL"
                                ? "bg-gradient-to-r from-[#881365] to-[#E5007D]"
                                : tier === "HIGH"
                                ? "bg-gradient-to-r from-[#5926B6] to-[#4F46E5]"
                                : tier === "MEDIUM"
                                ? "bg-gradient-to-r from-[#0284C7] to-[#1ABDD6]"
                                : "bg-gradient-to-r from-[#0D9488] to-[#00C8A8]"
                            }`}
                          >
                            {tier}
                          </span>
                        </td>
                        <td className="py-3.5 px-4" onClick={(e) => e.stopPropagation()}>
                          {(role === "admin" || role === "analyst") && (
                            <button
                              onClick={() => toggleFindingStatus(f)}
                              className={`text-xs font-bold px-3 py-1 rounded-full border cursor-pointer transition-all ${
                                isResolved
                                  ? "bg-emerald-500/15 text-emerald-500 border-emerald-500/30"
                                  : darkMode
                                  ? "bg-white/5 text-white border-white/20 hover:border-[#00E5C4]"
                                  : "bg-white text-slate-700 border-slate-300 hover:border-[#8121D7]"
                              }`}
                            >
                              {isResolved ? "Resolved ✓" : "Mark Resolved"}
                            </button>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        ));
}
