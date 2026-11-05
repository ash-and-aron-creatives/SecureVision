"use client";
import type { SecureAppViewProps } from "@/types/views";

export function AuditView(props: SecureAppViewProps) {
  const {
    activeTab, tabAnimKey, surfaceCard, headingColor, mutedText,
    exportExecutiveReport, subSurfaceCard, role, auditLogs,
  } = props;
  return (activeTab === "audit" && role === "admin" && (
          <div key={`audit-${tabAnimKey}`} className={`rounded-3xl p-6 md:p-8 border sv-tab-transition ${surfaceCard}`}>
            <div className="flex flex-wrap items-center justify-between gap-4 mb-5">
              <div>
                <h2 className={`text-2xl font-extrabold ${headingColor}`}>
                  Immutable Security Audit Log
                </h2>
                <p className={`text-xs ${mutedText}`}>
                  Cryptographically verifiable operator and backend scoring trail
                </p>
              </div>
              <button
                onClick={exportExecutiveReport}
                className="px-4 py-2 rounded-full text-xs font-bold bg-gradient-to-r from-[#8121D7] to-[#00B89E] text-white shadow-sm cursor-pointer"
              >
                ↓ Download Executive Audit Report
              </button>
            </div>
            <div className="space-y-2.5">
              {auditLogs.map((log, idx) => (
                <div
                  key={log.id}
                  style={{ animationDelay: `${idx * 0.06}s` }}
                  className={`sv-card-pop p-4 rounded-2xl border transition-all flex items-center justify-between text-xs ${subSurfaceCard}`}
                >
                  <div>
                    <span className="font-extrabold text-[#00B89E] mr-2">[{log.action}]</span>
                    <span className={`font-semibold ${headingColor}`}>{log.user}</span>
                    <span className={`ml-2 ${mutedText}`}>{log.details}</span>
                  </div>
                  <span className={mutedText}>{log.timestamp || "Recorded"}</span>
                </div>
              ))}
            </div>
          </div>
        ));
}
