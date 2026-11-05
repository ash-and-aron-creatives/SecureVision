import type { LoginResponse } from "../types";
import type { ApiRequester } from "./types";

export function login(
  apiRequest: ApiRequester,
  username: string,
  password: string,
): Promise<LoginResponse> {
  const formBody = new URLSearchParams();
  formBody.append("username", username.trim());
  formBody.append("password", password);
  return apiRequest<LoginResponse>("/token", null, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: formBody,
  });
}
