import type { ImportCommit, ImportPreview } from "../types";
import type { ApiRequester } from "./types";

export function previewImport(
  apiRequest: ApiRequester,
  authToken: string,
  file: File,
  createMissingAssets: boolean,
  dateOrder: "dmy" | "mdy",
): Promise<ImportPreview> {
  const formData = new FormData();
  formData.append("file", file);
  formData.append("create_missing_assets", String(createMissingAssets));
  formData.append("date_order", dateOrder);
  return apiRequest<ImportPreview>("/imports/preview", authToken, {
    method: "POST",
    body: formData,
  });
}

export function commitImport(
  apiRequest: ApiRequester,
  authToken: string,
  file: File,
  createMissingAssets: boolean,
  dateOrder: "dmy" | "mdy",
): Promise<ImportCommit> {
  const formData = new FormData();
  formData.append("file", file);
  formData.append("create_missing_assets", String(createMissingAssets));
  formData.append("date_order", dateOrder);
  return apiRequest<ImportCommit>("/imports/commit", authToken, {
    method: "POST",
    body: formData,
  });
}
