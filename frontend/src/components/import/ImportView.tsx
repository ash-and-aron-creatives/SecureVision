"use client";
import type { SecureAppViewProps } from "@/types/views";

export function ImportView(props: SecureAppViewProps) {
  const {
    activeTab, tabAnimKey, surfaceCard, headingColor, mutedText,
    subSurfaceCard, handleCsvPreview, setCsvFile, setImportPreview, importPreview,
    handleCsvCommit,
  } = props;
  return (activeTab === "import" && (
          <div key={`import-${tabAnimKey}`} className={`rounded-3xl p-6 md:p-8 border max-w-2xl sv-tab-transition ${surfaceCard}`}>
            <h2 className={`text-2xl font-extrabold mb-1 ${headingColor}`}>
              Bulk Scanner CSV Ingestion
            </h2>
            <p className={`text-xs mb-6 ${mutedText}`}>
              Upload a supported scanner CSV to score findings through the backend.
            </p>
            <form onSubmit={handleCsvPreview} className="space-y-4">
              <div className={`border-2 border-dashed border-[#8121D7]/40 hover:border-[#00B89E] transition-colors rounded-2xl p-8 text-center ${subSurfaceCard}`}>
                <input
                  type="file"
                  accept=".csv"
                  onChange={(e) => {
                    setCsvFile(e.target.files ? e.target.files[0] : null);
                    setImportPreview(null);
                  }}
                  className={`text-sm ${mutedText}`}
                />
                <p className={`text-xs mt-2 ${mutedText}`}>
                  Required columns: asset_name, cve_id, date_found (YYYY-MM-DD)
                </p>
              </div>
              <button
                type="submit"
                className="px-6 py-3 rounded-full bg-gradient-to-r from-[#8121D7] to-[#1ABDD6] text-white font-bold text-xs shadow-md hover:scale-105 transition-all cursor-pointer"
              >
                Preview CSV
              </button>
            </form>
            {importPreview && (
              <div className="mt-6 space-y-4">
                <p className={`text-sm font-bold ${headingColor}`}>
                  {importPreview.summary.total} rows: {importPreview.summary.ok} valid, {importPreview.summary.error} errors, {importPreview.summary.duplicate} duplicates
                </p>
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs">
                    <thead className={mutedText}>
                      <tr>
                        <th className="p-2">Line</th>
                        <th className="p-2">Asset</th>
                        <th className="p-2">CVE</th>
                        <th className="p-2">Date</th>
                        <th className="p-2">Status</th>
                        <th className="p-2">Details</th>
                      </tr>
                    </thead>
                    <tbody>
                      {importPreview.rows.map((row) => (
                        <tr key={row.line} className="border-t border-slate-200/30">
                          <td className="p-2">{row.line}</td>
                          <td className="p-2">{row.asset_name}</td>
                          <td className="p-2">{row.cve_id}</td>
                          <td className="p-2">{row.date_found}</td>
                          <td className="p-2">{row.status}</td>
                          <td className="p-2">{row.reason}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                <button
                  type="button"
                  onClick={handleCsvCommit}
                  className="px-6 py-3 rounded-full bg-gradient-to-r from-[#8121D7] to-[#00B89E] text-white font-bold text-xs shadow-md hover:scale-105 transition-all cursor-pointer"
                >
                  Commit Import
                </button>
              </div>
            )}
          </div>
        ));
}
