"use client";

import {
  Bar,
  BarChart,
  CartesianGrid,
  Legend,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import type { ModelResults, PriorityMode } from "@/types";

interface ModelResultsViewProps {
  data: ModelResults | null;
  priorityMode: PriorityMode | null;
  loading: boolean;
  error: string | null;
  surfaceCard: string;
  headingColor: string;
  mutedText: string;
  darkMode: boolean;
}

function formatMetric(value: number | null): string {
  return value === null ? "not available" : value.toFixed(4);
}

export function ModelResultsView({
  data,
  priorityMode,
  loading,
  error,
  surfaceCard,
  headingColor,
  mutedText,
  darkMode,
}: ModelResultsViewProps) {
  const rows = data?.models ?? [];
  const prAucData = rows
    .filter((row) => row.pr_auc !== null)
    .map((row) => ({ name: `${row.name} (${row.dataset})`, "PR-AUC": row.pr_auc }));
  const topKData = rows
    .filter((row) => Object.keys(row.precision_at_k).length > 0)
    .map((row) => ({
      name: `${row.name} (${row.dataset})`,
      "P@50": row.precision_at_k["50"],
      "P@100": row.precision_at_k["100"],
      "P@500": row.precision_at_k["500"],
      "R@50": row.recall_at_k["50"],
      "R@100": row.recall_at_k["100"],
      "R@500": row.recall_at_k["500"],
    }));
  const chartColor = darkMode ? "#D5CDE6" : "#475569";

  return (
    <section className={`rounded-3xl border p-5 sm:p-7 ${surfaceCard}`}>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className={`text-2xl font-extrabold tracking-tight ${headingColor}`}>Model Results</h1>
          <p className={`mt-1 text-sm ${mutedText}`}>Recorded evaluation metrics only; missing metrics are not inferred.</p>
        </div>
        <span className="rounded-full border border-amber-400/40 bg-amber-400/10 px-3 py-1 text-xs font-bold text-amber-300">
          Active mode: {priorityMode ?? "loading"}
        </span>
      </div>

      {loading && <p className={`mt-6 text-sm ${mutedText}`}>Loading recorded model results…</p>}
      {error && <p role="alert" className="mt-6 rounded-xl bg-rose-500/10 p-4 text-sm text-rose-300">{error}</p>}

      {!loading && !error && data && (
        <>
          <div className="mt-5 rounded-2xl border border-amber-400/25 bg-amber-400/5 p-4">
            <p className="text-[11px] font-bold uppercase tracking-wider text-amber-300">Decision log conclusion</p>
            <p className={`mt-2 text-sm leading-relaxed ${headingColor}`}>{data.conclusion || "not available"}</p>
          </div>
          <p className={`mt-3 text-xs ${mutedText}`}>
            Validation 2025 comparison: training-CV-tuned Logistic Regression, Random Forest (152 features), XGBoost, CVSS-only, and EPSS hindsight baseline. The fixed-parameter Logistic Regression run from 2026-11-14 is retained as a historical row; existing Test 2026 rows are shown separately.
          </p>

          <div className={`mt-5 overflow-x-auto rounded-2xl border ${darkMode ? "border-white/10" : "border-slate-200"}`}>
            <table className="min-w-[1420px] w-full text-left text-xs">
              <thead className={darkMode ? "bg-white/5 text-white/60" : "bg-slate-50 text-slate-500"}>
                <tr>
                  {["Model", "Dataset / split", "PR-AUC", "Precision", "Recall", "F1", "P@50", "P@100", "P@500", "R@50", "R@100", "R@500", "ROC-AUC", "Notes"].map((label) => (
                    <th key={label} className="px-3 py-3 font-bold">{label}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {rows.map((row) => (
                  <tr key={`${row.name}-${row.dataset}`} className={`border-t ${darkMode ? "border-white/10 text-white/80" : "border-slate-100 text-slate-700"}`}>
                    <td className="px-3 py-3 font-semibold">{row.name}</td>
                    <td className="px-3 py-3">{row.dataset}</td>
                    <td className="px-3 py-3">{formatMetric(row.pr_auc)}{row.pr_auc_stddev === null ? "" : ` ± ${formatMetric(row.pr_auc_stddev)}`}</td>
                    <td className="px-3 py-3">{formatMetric(row.precision)}</td>
                    <td className="px-3 py-3">{formatMetric(row.recall)}</td>
                    <td className="px-3 py-3">{formatMetric(row.f1)}</td>
                    <td className="px-3 py-3">{formatMetric(row.precision_at_k["50"] ?? null)}</td>
                    <td className="px-3 py-3">{formatMetric(row.precision_at_k["100"] ?? null)}</td>
                    <td className="px-3 py-3">{formatMetric(row.precision_at_k["500"] ?? null)}</td>
                    <td className="px-3 py-3">{formatMetric(row.recall_at_k["50"] ?? null)}</td>
                    <td className="px-3 py-3">{formatMetric(row.recall_at_k["100"] ?? null)}</td>
                    <td className="px-3 py-3">{formatMetric(row.recall_at_k["500"] ?? null)}</td>
                    <td className="px-3 py-3">{formatMetric(row.roc_auc)}</td>
                    <td className="px-3 py-3">{row.note ?? "not available"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {prAucData.length > 0 && (
            <div className={`mt-5 rounded-2xl border p-4 ${darkMode ? "border-white/10 bg-white/5" : "border-slate-200 bg-white"}`}>
              <h2 className={`mb-3 text-sm font-bold ${headingColor}`}>Recorded PR-AUC</h2>
              <div className="h-72">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={prAucData} margin={{ left: 4, right: 12, bottom: 56 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke={darkMode ? "#ffffff20" : "#e2e8f0"} />
                    <XAxis dataKey="name" angle={-24} textAnchor="end" interval={0} height={72} tick={{ fill: chartColor, fontSize: 10 }} />
                    <YAxis tick={{ fill: chartColor, fontSize: 10 }} />
                    <Tooltip />
                    <Bar dataKey="PR-AUC" fill="#00B89E" radius={[5, 5, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>
          )}

          {topKData.length > 0 && (
            <div className={`mt-5 rounded-2xl border p-4 ${darkMode ? "border-white/10 bg-white/5" : "border-slate-200 bg-white"}`}>
              <h2 className={`mb-3 text-sm font-bold ${headingColor}`}>Recorded precision at K</h2>
              <div className="h-72">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={topKData} margin={{ left: 4, right: 12, bottom: 56 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke={darkMode ? "#ffffff20" : "#e2e8f0"} />
                    <XAxis dataKey="name" angle={-24} textAnchor="end" interval={0} height={72} tick={{ fill: chartColor, fontSize: 10 }} />
                    <YAxis tick={{ fill: chartColor, fontSize: 10 }} />
                    <Tooltip />
                    <Legend />
                    <Bar dataKey="P@50" fill="#8121D7" radius={[4, 4, 0, 0]} />
                    <Bar dataKey="P@100" fill="#3B82F6" radius={[4, 4, 0, 0]} />
                    <Bar dataKey="P@500" fill="#00B89E" radius={[4, 4, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>
          )}

          <p className={`mt-5 text-xs ${mutedText}`}>Sources: {data.source_files.length ? data.source_files.join(", ") : "not available"}</p>
        </>
      )}
    </section>
  );
}
