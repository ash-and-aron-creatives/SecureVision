import type { UserItem } from "../types";
import type { ApiRequester } from "./types";

export function createUser(
  apiRequest: ApiRequester,
  authToken: string,
  payload: { username: string; password: string; role: string },
): Promise<UserItem> {
  return apiRequest<UserItem>("/users", authToken, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}

export function fetchUsers(apiRequest: ApiRequester, authToken: string): Promise<UserItem[]> {
  return apiRequest<UserItem[]>("/users", authToken);
}
