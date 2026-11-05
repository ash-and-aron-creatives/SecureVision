"use client";
import type { SecureAppViewProps } from "@/types/views";

export function DashboardView(props: SecureAppViewProps) {
  const {
    activeTab, tabAnimKey, surfaceCard, headingColor, mutedText,
    switchTab, darkMode, exportExecutiveReport, criticalCount, highCount,
    mediumCount, lowCount, subSurfaceCard, itemSurface, getTier,
    weeklyBars, completionPct, totalCount, resolvedCount, displayFindings,
    setTierFilter, setSelectedFinding,
  } = props;
  return (activeTab === "dashboard" && (
          <div key={`dash-${tabAnimKey}`} className={`rounded-3xl p-4 sm:p-6 md:p-8 border space-y-6 sv-tab-transition transition-colors duration-300 ${surfaceCard}`}>
            {/* Title Row + Action Buttons */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
              <div>
                <h1 className={`text-2xl sm:text-3xl font-extrabold tracking-tight ${headingColor}`}>
                  Dashboard
                </h1>
                <p className={`text-xs sm:text-sm mt-1 ${mutedText}`}>
                  Prioritize, triage, and remediate critical vulnerabilities with deterministic precision.
                </p>
              </div>
              <div className="flex flex-wrap sm:flex-nowrap items-center gap-2 sm:gap-2.5 shrink-0 whitespace-nowrap">
                <button
                  onClick={() => switchTab("scan")}
                  className="inline-flex items-center gap-2 px-4 sm:px-5 py-2.5 rounded-full bg-gradient-to-r from-[#5926B6] to-[#8121D7] hover:from-[#4C1D95] hover:to-[#6D28D9] text-white text-xs font-bold shadow-md hover:-translate-y-0.5 transition-all cursor-pointer"
                >
                  <span>+ New Scan</span>
                </button>
                <button
                  onClick={() => switchTab("import")}
                  className={`inline-flex items-center gap-2 px-4 sm:px-5 py-2.5 rounded-full border text-xs font-bold hover:-translate-y-0.5 transition-all cursor-pointer ${
                    darkMode
                      ? "bg-white/5 hover:bg-white/15 text-white border-white/20"
                      : "bg-white hover:bg-slate-50 text-[#2B125A] border-slate-300"
                  }`}
                >
                  <span>Import Data</span>
                </button>
                <button
                  onClick={exportExecutiveReport}
                  className="inline-flex items-center gap-1.5 px-4 py-2.5 rounded-full bg-[#00E5C4]/15 hover:bg-[#00E5C4]/25 text-[#008B76] dark:text-[#00E5C4] border border-[#00E5C4]/30 text-xs font-bold hover:-translate-y-0.5 transition-all cursor-pointer"
                >
                  <span>Export Report</span>
                </button>
              </div>
            </div>

            {/* ROW 1: 4 DISTINCT COLORED GRADIENT KPI CARDS */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
              {/* Card 1: CRITICAL */}
              <div
                style={{ animationDelay: "0.04s" }}
                onClick={() => { setTierFilter("CRITICAL"); switchTab("queue"); }}
                className="sv-card-pop rounded-3xl p-6 bg-gradient-to-br from-[#2B0948] via-[#881365] to-[#E5007D] text-white shadow-[0_12px_30px_rgba(229,0,125,0.25)] hover:-translate-y-1.5 hover:shadow-[0_18px_38px_rgba(229,0,125,0.35)] transition-all duration-300 relative overflow-hidden cursor-pointer group"
              >
                <div className="absolute -right-8 -top-8 w-28 h-28 rounded-full bg-white/10 blur-xl pointer-events-none group-hover:scale-125 transition-transform"></div>
                <div className="flex items-center justify-between gap-2 mb-3 relative z-10">
                  <span className="text-sm font-semibold text-white/95 whitespace-nowrap">Critical (Open)</span>
                  <span className="w-8 h-8 rounded-full bg-white text-[#881365] flex items-center justify-center shrink-0 group-hover:rotate-45 transition-transform duration-300 shadow-sm">
                    <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth="2.5" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" d="M7 17L17 7M7 7h10v10" />
                    </svg>
                  </span>
                </div>
                <div className="text-5xl font-extrabold tracking-tight mb-4 relative z-10">
                  {criticalCount}
                </div>
                <div className="inline-flex items-center gap-1.5 text-[11px] text-pink-100 font-semibold relative z-10">
                  <span className="px-2 py-0.5 rounded-md bg-white/20 text-white font-bold backdrop-blur-xs">24h SLA</span>
                  <span>Weaponized / KEV active</span>
                </div>
              </div>

              {/* Card 2: HIGH */}
              <div
                style={{ animationDelay: "0.10s" }}
                onClick={() => { setTierFilter("HIGH"); switchTab("queue"); }}
                className="sv-card-pop rounded-3xl p-6 bg-gradient-to-br from-[#3B147A] via-[#6D28D9] to-[#4F46E5] text-white shadow-[0_12px_30px_rgba(109,40,217,0.24)] hover:-translate-y-1.5 hover:shadow-[0_18px_38px_rgba(109,40,217,0.35)] transition-all duration-300 relative overflow-hidden cursor-pointer group"
              >
                <div className="absolute -right-8 -top-8 w-28 h-28 rounded-full bg-[#00E5C4]/15 blur-xl pointer-events-none group-hover:scale-125 transition-transform"></div>
                <div className="flex items-center justify-between gap-2 mb-3 relative z-10">
                  <span className="text-sm font-semibold text-white/95 whitespace-nowrap">High (Open)</span>
                  <span className="w-8 h-8 rounded-full bg-white text-[#5926B6] flex items-center justify-center shrink-0 group-hover:rotate-45 transition-transform duration-300 shadow-sm">
                    <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth="2.5" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" d="M7 17L17 7M7 7h10v10" />
                    </svg>
                  </span>
                </div>
                <div className="text-5xl font-extrabold tracking-tight mb-4 relative z-10">
                  {highCount}
                </div>
                <div className="inline-flex items-center gap-1.5 text-[11px] text-indigo-100 font-semibold relative z-10">
                  <span className="px-2 py-0.5 rounded-md bg-white/20 text-white font-bold backdrop-blur-xs">72h SLA</span>
                  <span>Public exploit PoC</span>
                </div>
              </div>

              {/* Card 3: MEDIUM */}
              <div
                style={{ animationDelay: "0.16s" }}
                onClick={() => { setTierFilter("MEDIUM"); switchTab("queue"); }}
                className="sv-card-pop rounded-3xl p-6 bg-gradient-to-br from-[#0F3F6E] via-[#0284C7] to-[#1ABDD6] text-white shadow-[0_12px_30px_rgba(26,189,214,0.24)] hover:-translate-y-1.5 hover:shadow-[0_18px_38px_rgba(26,189,214,0.35)] transition-all duration-300 relative overflow-hidden cursor-pointer group"
              >
                <div className="absolute -right-8 -top-8 w-28 h-28 rounded-full bg-white/15 blur-xl pointer-events-none group-hover:scale-125 transition-transform"></div>
                <div className="flex items-center justify-between gap-2 mb-3 relative z-10">
                  <span className="text-sm font-semibold text-white/95 whitespace-nowrap">Medium (Open)</span>
                  <span className="w-8 h-8 rounded-full bg-white text-[#0284C7] flex items-center justify-center shrink-0 group-hover:rotate-45 transition-transform duration-300 shadow-sm">
                    <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth="2.5" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" d="M7 17L17 7M7 7h10v10" />
                    </svg>
                  </span>
                </div>
                <div className="text-5xl font-extrabold tracking-tight mb-4 relative z-10">
                  {mediumCount}
                </div>
                <div className="inline-flex items-center gap-1.5 text-[11px] text-cyan-50 font-semibold relative z-10">
                  <span className="px-2 py-0.5 rounded-md bg-white/20 text-white font-bold backdrop-blur-xs">14d SLA</span>
                  <span>Scheduled patch cycle</span>
                </div>
              </div>

              {/* Card 4: LOW */}
              <div
                style={{ animationDelay: "0.22s" }}
                onClick={() => { setTierFilter("LOW"); switchTab("queue"); }}
                className="sv-card-pop rounded-3xl p-6 bg-gradient-to-br from-[#0B3B3C] via-[#0D9488] to-[#00C8A8] text-white shadow-[0_12px_30px_rgba(13,148,136,0.24)] hover:-translate-y-1.5 hover:shadow-[0_18px_38px_rgba(13,148,136,0.35)] transition-all duration-300 relative overflow-hidden cursor-pointer group"
              >
                <div className="absolute -right-8 -top-8 w-28 h-28 rounded-full bg-white/15 blur-xl pointer-events-none group-hover:scale-125 transition-transform"></div>
                <div className="flex items-center justify-between gap-2 mb-3 relative z-10">
                  <span className="text-sm font-semibold text-white/95 whitespace-nowrap">Low (Open)</span>
                  <span className="w-8 h-8 rounded-full bg-white text-[#0D9488] flex items-center justify-center shrink-0 group-hover:rotate-45 transition-transform duration-300 shadow-sm">
                    <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth="2.5" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" d="M7 17L17 7M7 7h10v10" />
                    </svg>
                  </span>
                </div>
                <div className="text-5xl font-extrabold tracking-tight mb-4 relative z-10">
                  {lowCount}
                </div>
                <div className="inline-flex items-center gap-1.5 text-[11px] text-emerald-50 font-semibold relative z-10">
                  <span className="px-2 py-0.5 rounded-md bg-white/20 text-white font-bold backdrop-blur-xs">30d SLA</span>
                  <span>Internal / non-exploitable</span>
                </div>
              </div>
            </div>

            {/* ROW 2: EXECUTIVE SPLINE AREA ANALYTICS GRAPH (7 COLS) + TOP PRIORITY QUEUE (5 COLS) */}
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
              {/* Col 1 (7 cols): Smooth Dual-Curve Area Analytics Graph */}
              <div
                style={{ animationDelay: "0.26s" }}
                className={`sv-card-pop lg:col-span-7 rounded-3xl p-5 sm:p-6 md:p-7 border flex flex-col justify-between relative overflow-hidden ${subSurfaceCard}`}
              >
                <div className="flex flex-wrap items-center justify-between gap-4 mb-4">
                  <div>
                    <div className="flex items-center gap-2.5">
                      <h3 className={`text-lg font-extrabold ${headingColor}`}>
                        Threat Exposure & Remediation Velocity
                      </h3>
                      <span className="text-[10px] font-extrabold uppercase px-2.5 py-0.5 rounded-full bg-[#00E5C4]/20 text-[#00B89E]">
                        Live Telemetry
                      </span>
                    </div>
                    <p className={`text-xs mt-0.5 ${mutedText}`}>
                      30-day correlation between weaponized KEV detections and verified patch mitigations
                    </p>
                  </div>

                  <div className="flex items-center gap-4 text-xs font-semibold">
                    <span className={`flex items-center gap-1.5 ${darkMode ? "text-white/80" : "text-slate-600"}`}>
                      <span className="w-3 h-3 rounded-full bg-gradient-to-r from-[#8121D7] to-[#E5007D] inline-block shadow-xs"></span>
                      Critical / KEV Ingested
                    </span>
                    <span className={`flex items-center gap-1.5 ${darkMode ? "text-white/80" : "text-slate-600"}`}>
                      <span className="w-3 h-3 rounded-full bg-gradient-to-r from-[#00E5C4] to-[#1ABDD6] inline-block shadow-xs"></span>
                      Remediated Within SLA
                    </span>
                  </div>
                </div>

                {/* Animated SVG Dual-Area Spline Chart */}
                <div className="relative w-full h-56 my-1">
                  <svg viewBox="0 0 700 220" className="w-full h-full overflow-visible" preserveAspectRatio="none">
                    <defs>
                      <linearGradient id="areaPurple" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="#8121D7" stopOpacity="0.38" />
                        <stop offset="65%" stopColor="#E5007D" stopOpacity="0.10" />
                        <stop offset="100%" stopColor="#8121D7" stopOpacity="0.0" />
                      </linearGradient>
                      <linearGradient id="areaCyan" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="#00E5C4" stopOpacity="0.42" />
                        <stop offset="70%" stopColor="#1ABDD6" stopOpacity="0.12" />
                        <stop offset="100%" stopColor="#00E5C4" stopOpacity="0.0" />
                      </linearGradient>
                      <linearGradient id="linePurple" x1="0" y1="0" x2="1" y2="0">
                        <stop offset="0%" stopColor="#8121D7" />
                        <stop offset="50%" stopColor="#E5007D" />
                        <stop offset="100%" stopColor="#8121D7" />
                      </linearGradient>
                      <linearGradient id="lineCyan" x1="0" y1="0" x2="1" y2="0">
                        <stop offset="0%" stopColor="#0284C7" />
                        <stop offset="50%" stopColor="#00E5C4" />
                        <stop offset="100%" stopColor="#00B89E" />
                      </linearGradient>
                    </defs>

                    {[35, 80, 125, 170].map((y, idx) => (
                      <g key={idx}>
                        <line
                          x1="35"
                          y1={y}
                          x2="685"
                          y2={y}
                          stroke={darkMode ? "rgba(255,255,255,0.08)" : "#E2E8F0"}
                          strokeDasharray="4 4"
                          strokeWidth="1"
                        />
                        <text x="6" y={y + 4} className="fill-slate-400 text-[10px] font-semibold">
                          {100 - idx * 25}
                        </text>
                      </g>
                    ))}

                    <path
                      d="M 40 145 C 110 120, 155 60, 220 78 C 285 95, 330 42, 395 55 C 460 68, 515 115, 575 88 C 620 68, 655 95, 680 105 L 680 190 L 40 190 Z"
                      fill="url(#areaPurple)"
                    />
                    <path
                      d="M 40 145 C 110 120, 155 60, 220 78 C 285 95, 330 42, 395 55 C 460 68, 515 115, 575 88 C 620 68, 655 95, 680 105"
                      fill="none"
                      stroke="url(#linePurple)"
                      strokeWidth="3.5"
                      strokeLinecap="round"
                    />

                    <path
                      d="M 40 165 C 110 150, 160 110, 220 118 C 285 125, 335 85, 395 72 C 460 58, 515 65, 575 44 C 620 30, 655 38, 680 28 L 680 190 L 40 190 Z"
                      fill="url(#areaCyan)"
                    />
                    <path
                      d="M 40 165 C 110 150, 160 110, 220 118 C 285 125, 335 85, 395 72 C 460 58, 515 65, 575 44 C 620 30, 655 38, 680 28"
                      fill="none"
                      stroke="url(#lineCyan)"
                      strokeWidth="3.5"
                      strokeLinecap="round"
                    />

                    {[
                      { cx: 220, cy: 78, color: "#E5007D" },
                      { cx: 395, cy: 55, color: "#8121D7" },
                      { cx: 575, cy: 44, color: "#00B89E" },
                      { cx: 680, cy: 28, color: "#00E5C4" },
                    ].map((pt, i) => (
                      <g key={i}>
                        <circle cx={pt.cx} cy={pt.cy} r="6" fill="#fff" stroke={pt.color} strokeWidth="3" />
                      </g>
                    ))}

                    <g transform="translate(525, 8)">
                      <rect x="0" y="0" width="96" height="24" rx="12" fill="#1D0C3B" />
                      <text x="48" y="15" textAnchor="middle" className="fill-[#00E5C4] text-[10px] font-bold">
                        +94% SLA Met
                      </text>
                    </g>

                    {[
                      { x: 45, label: "Wk 1" },
                      { x: 170, label: "Wk 2" },
                      { x: 295, label: "Wk 3" },
                      { x: 420, label: "Wk 4" },
                      { x: 545, label: "Wk 5" },
                      { x: 665, label: "Now" },
                    ].map((t, idx) => (
                      <text
                        key={idx}
                        x={t.x}
                        y="212"
                        textAnchor="middle"
                        className="fill-slate-400 text-[11px] font-semibold"
                      >
                        {t.label}
                      </text>
                    ))}
                  </svg>
                </div>

                {/* Bottom KPI Mini-Cards inside Graph Card (Clean 3-Row Stack - Zero Clipping) */}
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3.5 pt-4">
                  <div className={`p-4 rounded-2xl border overflow-hidden flex flex-col justify-between gap-1.5 ${itemSurface}`}>
                    <span className={`text-[11px] font-bold uppercase tracking-wide leading-snug ${mutedText}`}>
                      Noise Reduction
                    </span>
                    <div className={`text-2xl font-extrabold tracking-tight tabular-nums ${headingColor}`}>
                      85.4%
                    </div>
                    <div>
                      <span className="inline-flex items-center text-[10px] font-bold px-2.5 py-0.5 rounded-full bg-[#00E5C4]/15 text-[#008B76] dark:text-[#00E5C4]">
                        Based on backend findings
                      </span>
                    </div>
                  </div>

                  <div className={`p-4 rounded-2xl border overflow-hidden flex flex-col justify-between gap-1.5 ${itemSurface}`}>
                    <span className={`text-[11px] font-bold uppercase tracking-wide leading-snug ${mutedText}`}>
                      Mean Time to Triage
                    </span>
                    <div className={`text-2xl font-extrabold tracking-tight tabular-nums ${headingColor}`}>
                      1.8 hrs
                    </div>
                    <div>
                      <span className="inline-flex items-center text-[10px] font-bold px-2.5 py-0.5 rounded-full bg-[#8121D7]/15 text-[#8121D7] dark:text-[#00E5C4]">
                        ⚡ -64% faster
                      </span>
                    </div>
                  </div>

                  <div className={`p-4 rounded-2xl border overflow-hidden flex flex-col justify-between gap-1.5 ${itemSurface}`}>
                    <span className={`text-[11px] font-bold uppercase tracking-wide leading-snug ${mutedText}`}>
                      SLA Compliance
                    </span>
                    <div className="text-2xl font-extrabold tracking-tight text-[#00B89E] tabular-nums">
                      99.2%
                    </div>
                    <div>
                      <span className={`inline-flex items-center text-[10px] font-bold px-2.5 py-0.5 rounded-full bg-slate-500/10 ${mutedText}`}>
                        ⏱ 24h Critical SLA
                      </span>
                    </div>
                  </div>
                </div>
              </div>

              {/* Col 2 (5 cols): Streamlined Top Priority Queue */}
              <div
                style={{ animationDelay: "0.34s" }}
                className={`sv-card-pop lg:col-span-5 rounded-3xl p-5 sm:p-6 md:p-7 border flex flex-col justify-between ${subSurfaceCard}`}
              >
                <div>
                  <div className="flex items-center justify-between gap-2 mb-5">
                    <div>
                      <h3 className={`text-lg font-extrabold ${headingColor}`}>Priority Queue</h3>
                      <p className={`text-xs ${mutedText}`}>Click a finding to view the backend scoring explanation</p>
                    </div>
                    <button
                      onClick={() => switchTab("queue")}
                      className={`text-xs font-bold px-3.5 py-1.5 rounded-full border transition-colors cursor-pointer shrink-0 ${
                        darkMode
                          ? "bg-white/5 border-white/15 text-[#00E5C4] hover:bg-[#00E5C4] hover:text-[#120524]"
                          : "bg-white border-slate-200 text-[#8121D7] hover:bg-[#8121D7] hover:text-white shadow-2xs"
                      }`}
                    >
                      View All →
                    </button>
                  </div>

                  <div className="space-y-2.5">
                    {displayFindings.slice(0, 5).map((f, i) => (
                        <div
                          key={f.id}
                          onClick={() => setSelectedFinding(f)}
                          className={`flex items-center justify-between gap-3 p-3 rounded-2xl border hover:shadow-sm hover:translate-x-1 transition-all cursor-pointer ${itemSurface}`}
                        >
                          <div className="flex items-center gap-3 min-w-0 flex-1">
                            <span
                              className={`w-10 h-10 rounded-xl flex items-center justify-center text-white text-xs font-extrabold shrink-0 shadow-xs ${
                                i === 0
                                  ? "bg-gradient-to-br from-[#881365] to-[#E5007D]"
                                  : i === 1
                                  ? "bg-gradient-to-br from-[#3B147A] to-[#8121D7]"
                                  : i === 2
                                  ? "bg-gradient-to-br from-[#5926B6] to-[#4F46E5]"
                                  : i === 3
                                  ? "bg-gradient-to-br from-[#0284C7] to-[#1ABDD6]"
                                  : "bg-gradient-to-br from-[#0D9488] to-[#00C8A8]"
                              }`}
                            >
                              {f.score}/4
                            </span>
                            <div className="min-w-0 flex-1">
                              <p className={`text-xs font-extrabold tracking-tight whitespace-nowrap ${headingColor}`}>
                                {f.cve_id}
                              </p>
                              <p className={`text-[11px] whitespace-nowrap mt-0.5 ${mutedText}`}>
                                {f.asset_name} • <span className="font-semibold text-[#00B89E]">CVSS {f.cvss_score}</span>
                              </p>
                            </div>
                          </div>
                          <div className="flex flex-col items-end gap-1 shrink-0">
                            <span className="text-[10px] font-extrabold px-2.5 py-0.5 rounded-full bg-[#8121D7]/15 text-[#8121D7] dark:text-[#00E5C4]">
                              {getTier(f)}
                            </span>
                          </div>
                        </div>
                    ))}
                  </div>
                </div>

                <button
                  onClick={() => switchTab("scan")}
                  className="mt-5 w-full py-3 rounded-2xl bg-gradient-to-r from-[#1D0C3B] via-[#4C2396] to-[#00B89E] hover:opacity-95 text-white text-xs font-bold shadow-md transition-all cursor-pointer"
                >
                  + Evaluate New CVE Finding
                </button>
              </div>
            </div>

            {/* ROW 3: 7-DAY CAPSULE VELOCITY CHART (7 COLS) + REMEDIATION GAUGE & 2X2 SEVERITY GRID (5 COLS) */}
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
              {/* Col 1 (7 cols): Weekly Ingestion Capsule Chart */}
              <div
                style={{ animationDelay: "0.42s" }}
                className={`sv-card-pop lg:col-span-7 rounded-3xl p-5 sm:p-6 md:p-7 border flex flex-col justify-between ${subSurfaceCard}`}
              >
                <div className="flex flex-wrap items-center justify-between gap-2 mb-6">
                  <div>
                    <h3 className={`text-lg font-extrabold ${headingColor}`}>
                      Weekly Scanner Ingestion
                    </h3>
                    <p className={`text-xs ${mutedText}`}>
                      Daily CVE batch evaluations across Nessus, Qualys & Trivy feeds
                    </p>
                  </div>
                  <span className="text-[11px] font-bold px-3 py-1 rounded-full bg-[#8121D7]/15 text-[#8121D7] dark:text-[#00E5C4] flex items-center gap-1.5">
                    <span className="w-2 h-2 rounded-full bg-[#00E5C4] animate-ping"></span>
                    Backend data
                  </span>
                </div>

                <div className="grid grid-cols-7 gap-3 sm:gap-4 items-end h-48 pt-4 px-1 sm:px-2">
                  {weeklyBars.map((bar, idx) => (
                    <div key={idx} className="flex flex-col items-center h-full justify-end group">
                      <span className="text-[11px] font-extrabold text-[#8121D7] dark:text-[#00E5C4] mb-1.5 opacity-85 group-hover:opacity-100 group-hover:-translate-y-0.5 transition-all">
                        {bar.label}
                      </span>
                      <div
                        style={{ height: bar.height, animationDelay: `${0.15 + idx * 0.07}s` }}
                        className={`sv-bar-grow w-full max-w-[48px] rounded-full transition-all duration-300 group-hover:scale-105 ${
                          bar.type === "purple"
                            ? "bg-gradient-to-b from-[#8121D7] to-[#4C2396] shadow-md"
                            : bar.type === "cyan"
                            ? "bg-gradient-to-b from-[#00E5C4] to-[#1ABDD6] shadow-md"
                            : bar.type === "deep"
                            ? "bg-gradient-to-b from-[#2B125A] to-[#E5007D] shadow-md"
                            : "sv-striped-bar"
                        }`}
                      ></div>
                      <span className={`text-xs font-bold mt-2.5 ${mutedText}`}>{bar.day}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Col 2 (5 cols): Remediation Progress Gauge + Spacious 2x2 Tier Grid */}
              <div
                style={{ animationDelay: "0.50s" }}
                className={`sv-card-pop lg:col-span-5 rounded-3xl p-5 sm:p-6 md:p-7 border flex flex-col justify-between ${subSurfaceCard}`}
              >
                <div className="flex items-center justify-between gap-2">
                  <div>
                    <h3 className={`text-lg font-extrabold ${headingColor}`}>Remediation Progress</h3>
                    <p className={`text-xs ${mutedText}`}>Overall SLA mitigation & tier breakdown</p>
                  </div>
                  <span className="text-xs font-bold text-[#00B89E] bg-[#00E5C4]/20 px-3 py-1 rounded-full shrink-0">
                    SLA Healthy
                  </span>
                </div>

                {/* Centered Semi-Circle Gauge */}
                <div className="flex flex-col items-center justify-center my-3">
                  <svg viewBox="0 0 200 115" className="w-44 h-24 overflow-visible">
                    <defs>
                      <linearGradient id="gaugeGrad" x1="0%" y1="0%" x2="100%" y2="0%">
                        <stop offset="0%" stopColor="#00E5C4" />
                        <stop offset="55%" stopColor="#8121D7" />
                        <stop offset="100%" stopColor="#E5007D" />
                      </linearGradient>
                    </defs>
                    <path
                      d="M 20 100 A 80 80 0 0 1 180 100"
                      fill="none"
                      stroke={darkMode ? "rgba(255,255,255,0.12)" : "#E2E8F0"}
                      strokeWidth="22"
                      strokeLinecap="round"
                    />
                    <path
                      d="M 20 100 A 80 80 0 0 1 180 100"
                      fill="none"
                      stroke="url(#gaugeGrad)"
                      strokeWidth="22"
                      strokeLinecap="round"
                      strokeDasharray="251.2"
                      strokeDashoffset={251.2 - (251.2 * completionPct) / 100}
                      className="sv-gauge-arc"
                    />
                  </svg>
                  <div className="-mt-8 text-center">
                    <span className={`text-3xl font-extrabold ${headingColor}`}>{completionPct}%</span>
                    <p className={`text-[11px] font-semibold ${mutedText}`}>Findings Mitigated</p>
                  </div>
                </div>

                {/* Spacious 2x2 Grid for Critical, High, Medium, Low */}
                <div className="grid grid-cols-2 gap-2.5 my-2">
                  {[
                    { label: "Critical", count: criticalCount, pct: Math.round((criticalCount / totalCount) * 100), bar: "from-[#881365] to-[#E5007D]", dot: "bg-[#E5007D]" },
                    { label: "High", count: highCount, pct: Math.round((highCount / totalCount) * 100), bar: "from-[#5926B6] to-[#4F46E5]", dot: "bg-[#6D28D9]" },
                    { label: "Medium", count: mediumCount, pct: Math.round((mediumCount / totalCount) * 100), bar: "from-[#0284C7] to-[#1ABDD6]", dot: "bg-[#0284C7]" },
                    { label: "Low", count: lowCount, pct: Math.round((lowCount / totalCount) * 100), bar: "from-[#0D9488] to-[#00C8A8]", dot: "bg-[#0D9488]" },
                  ].map((row, idx) => (
                    <div
                      key={idx}
                      onClick={() => { setTierFilter(row.label.toUpperCase()); switchTab("queue"); }}
                      className={`p-3 rounded-2xl border cursor-pointer transition-all ${itemSurface}`}
                    >
                      <div className="flex items-center justify-between gap-1 mb-1.5">
                        <span className="flex items-center gap-1.5 text-xs font-extrabold">
                          <span className={`w-2 h-2 rounded-full ${row.dot} shrink-0`}></span>
                          <span className={headingColor}>{row.label}</span>
                        </span>
                        <span className={`text-[11px] font-bold tabular-nums whitespace-nowrap ${mutedText}`}>
                          {row.count} ({row.pct}%)
                        </span>
                      </div>
                      <div className={`w-full h-2 rounded-full overflow-hidden ${darkMode ? "bg-white/10" : "bg-slate-200/80"}`}>
                        <div
                          style={{ width: `${Math.max(row.pct, 10)}%` }}
                          className={`h-full rounded-full bg-gradient-to-r ${row.bar}`}
                        ></div>
                      </div>
                    </div>
                  ))}
                </div>

                <div className={`w-full flex flex-wrap items-center justify-between gap-2 text-[11px] pt-3 border-t ${darkMode ? "border-white/10 text-white/70" : "border-slate-200/70 text-slate-500"}`}>
                  <span className="flex items-center gap-1.5 font-semibold whitespace-nowrap">
                    <span className="w-2.5 h-2.5 rounded-full bg-[#00E5C4]"></span>Mitigated ({resolvedCount})
                  </span>
                  <span className="flex items-center gap-1.5 font-semibold whitespace-nowrap">
                    <span className="w-2.5 h-2.5 rounded-full bg-[#8121D7]"></span>Open ({totalCount - resolvedCount})
                  </span>
                  <span className="text-[#00B89E] font-bold whitespace-nowrap">Total: {totalCount} CVEs</span>
                </div>
              </div>
            </div>
          </div>
        ));
}
