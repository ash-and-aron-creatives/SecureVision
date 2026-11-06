import type { ImportCommit, ImportPreview } from "../types";
import type { ApiRequester } from "./types";

export function previewImport(
  apiRequest: ApiRequester,
  authToken: string,
  file: File,
  createMissingAssets: boolean,
): Promise<ImportPreview> {
  const formData = new FormData();
  formData.append("file", file);
  formData.append("create_missing_assets", String(createMissingAssets));
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
): Promise<ImportCommit> {
  const formData = new FormData();
  formData.append("file", file);
  formData.append("create_missing_assets", String(createMissingAssets));
  return apiRequest<ImportCommit>("/imports/commit", authToken, {
    method: "POST",
    body: formData,
  });
}
