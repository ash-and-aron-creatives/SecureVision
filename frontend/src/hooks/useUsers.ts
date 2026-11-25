import { useState } from "react";
import type { FormEvent } from "react";
import { ApiRequestError } from "../api/client";
import {
  createUser,
  deactivateUser,
  deleteUser,
  reactivateUser,
  updateUser,
} from "../api/users";
import type { ApiRequester } from "../api/types";
import type { UserItem, UserRole } from "../types";

export function useUsers(
  token: string | null,
  apiRequest: ApiRequester,
  refreshAllData: (authToken: string) => Promise<boolean>,
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
      setNewUsername("");
      setNewPassword("");
      setActionMessage(`Operator ${created.username} (${created.role.toUpperCase()}) provisioned.`);
      await refreshAllData(token);
    } catch (userError) {
      setActionMessage(userError instanceof Error ? userError.message : "Unable to create user.");
    }
  };

  const handleUpdateUserRole = async (userId: number, role: UserRole) => {
    if (!token) return;
    try {
      await updateUser(apiRequest, token, userId, { role });
      setActionMessage("User role updated.");
      await refreshAllData(token);
    } catch (userError) {
      setActionMessage(userError instanceof Error ? userError.message : "Unable to update user role.");
    }
  };

  const handleResetUserPassword = async (userId: number, password: string) => {
    if (!token) return;
    try {
      await updateUser(apiRequest, token, userId, { password });
      setActionMessage("User password reset.");
      await refreshAllData(token);
    } catch (userError) {
      setActionMessage(userError instanceof Error ? userError.message : "Unable to reset user password.");
    }
  };

  const handleDeleteUser = async (user: UserItem) => {
    if (!token || !window.confirm(`Delete user "${user.username}"? This cannot be undone.`)) return;
    try {
      await deleteUser(apiRequest, token, user.id);
      setActionMessage(`User ${user.username} deleted.`);
      await refreshAllData(token);
    } catch (userError) {
      if (userError instanceof ApiRequestError && userError.status === 409) {
        setActionMessage(userError.message);
        return;
      }
      setActionMessage(userError instanceof Error ? userError.message : "Unable to delete user.");
    }
  };

  const handleDeactivateUser = async (user: UserItem) => {
    if (!token || !window.confirm(`Deactivate user "${user.username}"?`)) return;
    try {
      await deactivateUser(apiRequest, token, user.id);
      setActionMessage(`User ${user.username} deactivated.`);
      await refreshAllData(token);
    } catch (userError) {
      setActionMessage(userError instanceof Error ? userError.message : "Unable to deactivate user.");
    }
  };

  const handleReactivateUser = async (user: UserItem) => {
    if (!token) return;
    try {
      await reactivateUser(apiRequest, token, user.id);
      setActionMessage(`User ${user.username} reactivated.`);
      await refreshAllData(token);
    } catch (userError) {
      setActionMessage(userError instanceof Error ? userError.message : "Unable to reactivate user.");
    }
  };

  return {
    newUsername,
    setNewUsername,
    newPassword,
    setNewPassword,
    newRole,
    setNewRole,
    handleCreateUser,
    handleUpdateUserRole,
    handleResetUserPassword,
    handleDeleteUser,
    handleDeactivateUser,
    handleReactivateUser,
  };
}
