import { useState } from "react";
import type { FormEvent } from "react";
import { commitImport, previewImport } from "../api/import";
import type { ImportPreview } from "../types";
import type { ApiRequester } from "../api/types";

export function useImport(
  token: string | null,
  apiRequest: ApiRequester,
  setActionMessage: (message: string) => void,
  fetchAllData: (authToken: string) => Promise<unknown>,
) {
  const [csvFile, setCsvFile] = useState<File | null>(null);
  const [importPreview, setImportPreview] = useState<ImportPreview | null>(null);

  const handleCsvPreview = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (!csvFile || !token) {
      setActionMessage("Choose a CSV file before previewing.");
      return;
    }
    try {
      const result = await previewImport(apiRequest, token, csvFile);
      setImportPreview(result);
      setActionMessage(`Preview ready: ${result.summary.ok} valid, ${result.summary.error} errors, ${result.summary.duplicate} duplicates.`);
    } catch (importError) {
      setActionMessage(importError instanceof Error ? importError.message : "CSV preview failed.");
    }
  };

  const handleCsvCommit = async () => {
    if (!csvFile || !token || !importPreview) return;
    try {
      const result = await commitImport(apiRequest, token, csvFile);
      setActionMessage(`Backend imported ${result.imported} findings; ${result.skipped} skipped.`);
      await fetchAllData(token);
      setImportPreview(null);
      setCsvFile(null);
    } catch (importError) {
      setActionMessage(importError instanceof Error ? importError.message : "CSV import failed.");
    }
  };

  return {
    csvFile,
    setCsvFile,
    importPreview,
    setImportPreview,
    handleCsvPreview,
    handleCsvCommit,
  };
}
