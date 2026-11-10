"use client";
import type { SecureAppViewProps } from "@/types/views";

export function FindingDetailsDrawer(props: SecureAppViewProps) {
  const {
    getTier, toggleFindingStatus, selectedFinding, setSelectedFinding, role,
  } = props;
  return (selectedFinding && (() => {
        const tier = getTier(selectedFinding);
        const isResolved = selectedFinding.status.toUpperCase() === "RESOLVED";
        return (
          <div
            onClick={() => setSelectedFinding(null)}
            className="fixed inset-0 bg-black/60 backdrop-blur-xs z-50 flex justify-end"
          >
            <div
              onClick={(e) => e.stopPropagation()}
              className="sv-drawer-enter w-full max-w-lg bg-gradient-to-b from-[#1D0C3B] via-[#15082E] to-[#0B031D] text-white h-full p-6 md:p-8 overflow-y-auto border-l border-white/15 shadow-2xl flex flex-col justify-between"
            >
              <div>
                <div className="flex items-center justify-between pb-4 border-b border-white/10">
                  <div className="flex items-center gap-2.5">
                    <span className="px-2.5 py-1 rounded-md bg-[#00E5C4]/15 text-[#00E5C4] border border-[#00E5C4]/30 font-mono text-xs font-extrabold">
                      Deterministic tier
                    </span>
                  </div>
                  <button
                    onClick={() => setSelectedFinding(null)}
                    className="w-8 h-8 rounded-full bg-white/10 hover:bg-white/20 flex items-center justify-center text-sm cursor-pointer"
                  >
                    ✕
                  </button>
                </div>

                <div className="mt-6">
                  <div className="flex items-center justify-between gap-3">
                    <h2 className="text-2xl font-extrabold tracking-tight text-white">
                      {selectedFinding.cve_id}
                    </h2>
                    <span className="text-3xl font-extrabold text-[#00E5C4]">
                      {selectedFinding.score}<span className="text-xs text-white/50">/4</span>
                    </span>
                  </div>
                  <p className="text-sm text-white/75 mt-1">{selectedFinding.asset_name}</p>
                  <span className="mt-3 inline-flex text-[11px] font-bold px-2.5 py-1 rounded-full bg-[#E5007D]/25 text-pink-200 border border-[#E5007D]/40">
                    Priority: {tier}
                  </span>
                </div>

                <section className="mt-6 bg-white/5 border border-white/10 rounded-2xl p-5">
                  <h3 className="text-sm font-extrabold text-white">Deterministic tier</h3>
                  <p className="text-xs text-white/55 mt-1">The existing 320-rule matrix is the primary priority tier.</p>
                  <p className="text-sm text-white/90 leading-relaxed">
                    {selectedFinding.explanation.summary}
                  </p>
                  <dl className="mt-4 grid grid-cols-2 gap-3 text-xs">
                    <div><dt className="text-white/50">KEV</dt><dd>{selectedFinding.explanation.inputs.in_kev ? "Yes" : "No"}</dd></div>
                    <div><dt className="text-white/50">Internet-facing</dt><dd>{selectedFinding.explanation.inputs.internet_facing ? "Yes" : "No"}</dd></div>
                    <div><dt className="text-white/50">Criticality</dt><dd>{selectedFinding.explanation.inputs.criticality}/5</dd></div>
                    <div><dt className="text-white/50">EPSS percentile</dt><dd>{selectedFinding.explanation.inputs.epss_percentile ?? "Missing"}</dd></div>
                    <div><dt className="text-white/50">CVSS</dt><dd>{selectedFinding.explanation.inputs.cvss_score ?? "Missing"}</dd></div>
                  </dl>
                </section>

                <section className="mt-4 bg-[#00E5C4]/5 border border-[#00E5C4]/20 rounded-2xl p-5">
                  <h3 className="text-sm font-extrabold text-[#00E5C4]">
                    ML-assisted risk (experimental, advisory)
                  </h3>
                  <dl className="mt-4 grid grid-cols-2 gap-3 text-xs">
                    <div>
                      <dt className="text-white/50">Likelihood</dt>
                      <dd>{selectedFinding.ml_likelihood === null
                        ? "Unavailable"
                        : `${(selectedFinding.ml_likelihood * 100).toFixed(2)}%`}</dd>
                    </div>
                    <div><dt className="text-white/50">ML priority</dt><dd>{selectedFinding.ml_priority ?? "Unavailable"}</dd></div>
                    <div><dt className="text-white/50">ML risk</dt><dd>{selectedFinding.ml_risk === null ? "Unavailable" : selectedFinding.ml_risk.toFixed(6)}</dd></div>
                    <div><dt className="text-white/50">Model version</dt><dd>{selectedFinding.ml_model_version ?? "Unavailable"}</dd></div>
                  </dl>
                  <div className="mt-4">
                    <p className="text-xs font-bold text-white/70">Top influential factors</p>
                    {selectedFinding.ml_top_reasons?.length ? (
                      <ol className="mt-2 space-y-1.5 list-decimal list-inside text-xs text-white/80">
                        {selectedFinding.ml_top_reasons.slice(0, 3).map((reason) => <li key={reason}>{reason}</li>)}
                      </ol>
                    ) : (
                      <p className="mt-2 text-xs text-white/55">
                        {selectedFinding.ml_unavailable_reason ?? "Unavailable"}
                      </p>
                    )}
                  </div>
                  <p className="mt-4 text-xs text-white/80">
                    <span className="font-bold text-white/60">Recommended action: </span>
                    {selectedFinding.ml_recommended_action ?? "Unavailable"}
                  </p>
                  <p className="mt-4 border-t border-white/10 pt-3 text-[11px] leading-relaxed text-white/55">
                    Offline evaluation: PR-AUC 0.0114 vs CVSS 0.0117; this signal does not drive the tier.
                  </p>
                </section>
              </div>

              <div className="pt-6 border-t border-white/10 flex gap-3 mt-6">
                {(role === "admin" || role === "analyst") && (
                  <button
                    onClick={() => toggleFindingStatus(selectedFinding)}
                    className="flex-1 py-3 rounded-xl bg-gradient-to-r from-[#8121D7] to-[#00B89E] text-white font-bold text-xs shadow-lg cursor-pointer"
                  >
                    {isResolved ? "Reopen Finding" : "Mark Finding Resolved ✓"}
                  </button>
                )}
                <button
                  onClick={() => setSelectedFinding(null)}
                  className="px-5 py-3 rounded-xl bg-white/10 hover:bg-white/20 text-white font-bold text-xs cursor-pointer"
                >
                  Close
                </button>
              </div>
            </div>
          </div>
        );
      })());
}
