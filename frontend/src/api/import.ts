import type { ImportCommit, ImportPreview } from "../types";
import type { ApiRequester } from "./types";

export function previewImport(
  apiRequest: ApiRequester,
  authToken: string,
  file: File,
): Promise<ImportPreview> {
  const formData = new FormData();
  formData.append("file", file);
  return apiRequest<ImportPreview>("/imports/preview", authToken, {
    method: "POST",
    body: formData,
  });
}

export function commitImport(
  apiRequest: ApiRequester,
  authToken: string,
  file: File,
): Promise<ImportCommit> {
  const formData = new FormData();
  formData.append("file", file);
  return apiRequest<ImportCommit>("/imports/commit", authToken, {
    method: "POST",
    body: formData,
  });
}
