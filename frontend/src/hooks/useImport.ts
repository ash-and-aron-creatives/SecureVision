import { useState } from "react";
import type { FormEvent } from "react";
import { commitImport, previewImport } from "../api/import";
import type { ImportPreview } from "../types";
import type { ApiRequester } from "../api/types";

export function useImport(
  token: string | null,
  apiRequest: ApiRequester,
  setActionMessage: (message: string) => void,
  refreshAllData: (authToken: string) => Promise<boolean>,
) {
  const [csvFile, setCsvFile] = useState<File | null>(null);
  const [importPreview, setImportPreview] = useState<ImportPreview | null>(null);
  const [createMissingAssets, setCreateMissingAssets] = useState(false);
  const [dateOrder, setDateOrder] = useState<"dmy" | "mdy">("dmy");

  const handleCsvPreview = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (!csvFile || !token) {
      setActionMessage("Choose a CSV file before previewing.");
      return;
    }
    try {
      const result = await previewImport(
        apiRequest,
        token,
        csvFile,
        createMissingAssets,
        dateOrder,
      );
      setImportPreview(result);
      setActionMessage(`Preview ready (${result.detected_format}): ${result.summary.ok} valid, ${result.summary.error} errors, ${result.summary.duplicate} duplicates.`);
    } catch (importError) {
      setActionMessage(importError instanceof Error ? importError.message : "CSV preview failed.");
    }
  };

  const handleCsvCommit = async () => {
    if (!csvFile || !token || !importPreview || importPreview.summary.ok === 0) return;
    try {
      const result = await commitImport(
        apiRequest,
        token,
        csvFile,
        createMissingAssets,
        dateOrder,
      );
      setActionMessage(
        `Backend imported ${result.imported} findings; ${result.skipped} skipped. ` +
        `${result.ambiguous_date_rows} ambiguous date rows interpreted as ${dateOrder.toUpperCase()}.`,
      );
      await refreshAllData(token);
      setImportPreview(null);
      setCsvFile(null);
    } catch (importError) {
      setActionMessage(importError instanceof Error ? importError.message : "CSV import failed.");
    }
  };

  return {
    csvFile,
    setCsvFile,
    createMissingAssets,
    setCreateMissingAssets,
    dateOrder,
    setDateOrder,
    importPreview,
    setImportPreview,
    handleCsvPreview,
    handleCsvCommit,
  };
}
