const API_BASE = process.env.NEXT_PUBLIC_API_BASE || "http://localhost:8000";

function getErrorMessage(payload: unknown, fallback: string): string {
  if (typeof payload === "object" && payload !== null && "detail" in payload) {
    const detail = payload.detail;
    if (typeof detail === "string") return detail;
    if (Array.isArray(detail)) {
      return detail
        .map((item) =>
          typeof item === "object" && item !== null && "msg" in item && typeof item.msg === "string"
            ? item.msg
            : "",
        )
        .filter(Boolean)
        .join(", ") || fallback;
    }
    if (typeof detail === "object" && detail !== null) {
      const message = "message" in detail && typeof detail.message === "string"
        ? detail.message
        : "";
      const errors = "errors" in detail && Array.isArray(detail.errors)
        ? detail.errors.filter((item): item is string => typeof item === "string")
        : [];
      return [message, ...errors].filter(Boolean).join(" ") || fallback;
    }
  }
  return typeof payload === "string" && payload ? payload : fallback;
}

export class ApiRequestError extends Error {
  constructor(message: string, readonly status: number) {
    super(message);
    this.name = "ApiRequestError";
  }
}

export async function requestApi<T>(
  path: string,
  authToken: string | null,
  init: RequestInit = {},
): Promise<T> {
  const headers = new Headers(init.headers);
  if (authToken) headers.set("Authorization", `Bearer ${authToken}`);
  const response = await fetch(`${API_BASE}${path}`, { ...init, headers });
  const responseText = await response.text();
  let payload: unknown;
  try {
    payload = responseText ? JSON.parse(responseText) as unknown : undefined;
  } catch {
    payload = responseText;
  }

  if (!response.ok) {
    throw new ApiRequestError(
      getErrorMessage(payload, `Request failed (${response.status}).`),
      response.status,
    );
  }
  return payload as T;
}

function getDownloadFilename(disposition: string | null): string {
  const encoded = disposition?.match(/filename\*=UTF-8''([^;]+)/i)?.[1];
  const plain = disposition?.match(/filename="?([^";]+)"?/i)?.[1];
  let filename = plain || "securevision-report";
  if (encoded) {
    try {
      filename = decodeURIComponent(encoded);
    } catch {
      filename = plain || filename;
    }
  }
  return filename.replace(/[\\/]/g, "_");
}

export async function downloadApiFile(path: string, authToken: string): Promise<void> {
  const response = await fetch(`${API_BASE}${path}`, {
    headers: { Authorization: `Bearer ${authToken}` },
  });
  if (!response.ok) {
    const responseText = await response.text();
    let payload: unknown;
    try {
      payload = responseText ? JSON.parse(responseText) as unknown : undefined;
    } catch {
      payload = responseText;
    }
    throw new ApiRequestError(
      getErrorMessage(payload, `Request failed (${response.status}).`),
      response.status,
    );
  }

  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = getDownloadFilename(response.headers.get("Content-Disposition"));
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 0);
}
