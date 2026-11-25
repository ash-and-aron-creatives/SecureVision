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

export function updateUser(
  apiRequest: ApiRequester,
  authToken: string,
  userId: number,
  payload: { role?: string; password?: string },
): Promise<UserItem> {
  return apiRequest<UserItem>(`/users/${userId}`, authToken, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}

export function deleteUser(
  apiRequest: ApiRequester,
  authToken: string,
  userId: number,
): Promise<{ deleted: number; username: string }> {
  return apiRequest<{ deleted: number; username: string }>(`/users/${userId}`, authToken, {
    method: "DELETE",
  });
}

export function deactivateUser(
  apiRequest: ApiRequester,
  authToken: string,
  userId: number,
): Promise<UserItem> {
  return apiRequest<UserItem>(`/users/${userId}/deactivate`, authToken, {
    method: "POST",
  });
}

export function reactivateUser(
  apiRequest: ApiRequester,
  authToken: string,
  userId: number,
): Promise<UserItem> {
  return apiRequest<UserItem>(`/users/${userId}/reactivate`, authToken, {
    method: "POST",
  });
}
