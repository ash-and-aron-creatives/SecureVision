import { useState } from "react";
import type { FormEvent } from "react";
import { createUser } from "../api/users";
import type { ApiRequester } from "../api/types";
import type { UserItem } from "../types";

export function useUsers(
  token: string | null,
  apiRequest: ApiRequester,
  setUsers: (update: (current: UserItem[]) => UserItem[]) => void,
  setActionMessage: (message: string) => void,
) {
  const [newUsername, setNewUsername] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [newRole, setNewRole] = useState("analyst");

  const handleCreateUser = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (!newUsername || !token) return;
    try {
      const created = await createUser(apiRequest, token, {
        username: newUsername,
        password: newPassword,
        role: newRole,
      });
      setUsers((current) => [...current, created]);
      setNewUsername("");
      setNewPassword("");
      setActionMessage(`Operator ${created.username} (${created.role.toUpperCase()}) provisioned.`);
    } catch (userError) {
      setActionMessage(userError instanceof Error ? userError.message : "Unable to create user.");
    }
  };

  return { newUsername, setNewUsername, newPassword, setNewPassword, newRole, setNewRole, handleCreateUser };
}
