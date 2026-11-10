"use client";
import { useState } from "react";
import type { SecureAppViewProps } from "@/types/views";
import type { UserItem, UserRole } from "@/types";

interface UserCardProps {
  user: UserItem;
  currentUser: string;
  adminCount: number;
  darkMode: boolean;
  headingColor: string;
  mutedText: string;
  subSurfaceCard: string;
  onRoleChange: (userId: number, role: UserRole) => Promise<void>;
  onPasswordReset: (userId: number, password: string) => Promise<void>;
  onDelete: (user: UserItem) => Promise<void>;
  animationDelay: string;
}

function UserCard({
  user,
  currentUser,
  adminCount,
  darkMode,
  headingColor,
  mutedText,
  subSurfaceCard,
  onRoleChange,
  onPasswordReset,
  onDelete,
  animationDelay,
}: UserCardProps) {
  const [selectedRole, setSelectedRole] = useState<UserRole>(user.role);
  const [password, setPassword] = useState("");
  const isSelf = user.username === currentUser;
  const isLastAdmin = user.role === "admin" && adminCount <= 1;
  const cannotDemote = selectedRole !== "admin" && (isSelf || isLastAdmin);

  return (
    <div
      style={{ animationDelay }}
      className={`sv-card-pop p-5 rounded-2xl border hover:-translate-y-1 transition-all ${subSurfaceCard}`}
    >
      <div className="flex items-center justify-between gap-3 mb-4">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-full bg-gradient-to-tr from-[#8121D7] to-[#00E5C4] text-white font-bold text-xs flex items-center justify-center">
            {user.username.slice(0, 2).toUpperCase()}
          </div>
          <div>
            <p className={`font-bold text-sm ${headingColor}`}>{user.username}</p>
            <p className={`text-[11px] ${mutedText}`}>JWT Authenticated</p>
          </div>
        </div>
        <span className="px-2.5 py-1 rounded-full text-[11px] font-extrabold uppercase bg-[#8121D7]/15 text-[#8121D7] dark:text-[#00E5C4]">
          {user.role}
        </span>
      </div>
      <div className="space-y-3">
        <div className="flex gap-2">
          <select
            aria-label={`Role for ${user.username}`}
            value={selectedRole}
            onChange={(event) => {
              const nextRole = event.target.value;
              if (nextRole === "admin" || nextRole === "analyst" || nextRole === "viewer") {
                setSelectedRole(nextRole);
              }
            }}
            className={`min-w-0 flex-1 px-3 py-2 rounded-xl border text-xs ${darkMode ? "bg-[#15082E] border-white/15 text-white" : "bg-white border-slate-200"}`}
          >
            <option value="admin">Admin</option>
            <option value="analyst">Analyst</option>
            <option value="viewer">Viewer</option>
          </select>
          <button
            type="button"
            disabled={selectedRole === user.role || cannotDemote}
            onClick={() => void onRoleChange(user.id, selectedRole)}
            className="px-3 py-2 rounded-xl bg-[#8121D7]/15 text-[#8121D7] dark:text-[#00E5C4] text-xs font-bold disabled:opacity-40"
          >
            Save role
          </button>
        </div>
        {cannotDemote && (
          <p className="text-[11px] text-amber-500">
            {isSelf ? "You cannot demote your own account." : "At least one administrator must remain."}
          </p>
        )}
        <form
          className="flex gap-2"
          onSubmit={(event) => {
            event.preventDefault();
            if (password.length >= 8) {
              void onPasswordReset(user.id, password);
              setPassword("");
            }
          }}
        >
          <input
            type="password"
            aria-label={`New password for ${user.username}`}
            placeholder="New password (8+ chars)"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            className={`min-w-0 flex-1 px-3 py-2 rounded-xl border text-xs ${darkMode ? "bg-[#15082E] border-white/15 text-white" : "bg-white border-slate-200"}`}
          />
          <button
            type="submit"
            disabled={password.length < 8}
            className="px-3 py-2 rounded-xl bg-[#00E5C4]/15 text-[#008B76] dark:text-[#00E5C4] text-xs font-bold disabled:opacity-40"
          >
            Reset
          </button>
        </form>
        <button
          type="button"
          disabled={isSelf || isLastAdmin}
          onClick={() => void onDelete(user)}
          className="px-3 py-2 rounded-xl bg-rose-500/10 text-rose-500 text-xs font-bold disabled:opacity-40"
        >
          Delete user
        </button>
        {(isSelf || isLastAdmin) && (
          <p className="text-[11px] text-amber-500">
            {isSelf ? "You cannot delete your own account." : "At least one administrator must remain."}
          </p>
        )}
      </div>
    </div>
  );
}

export function UsersView(props: SecureAppViewProps) {
  const {
    activeTab, tabAnimKey, surfaceCard, headingColor, mutedText,
    darkMode, subSurfaceCard, role, handleCreateUser, newUsername,
    setNewUsername, newPassword, setNewPassword, newRole, setNewRole,
    users, currentUser, handleUpdateUserRole, handleResetUserPassword, handleDeleteUser,
  } = props;
  const adminCount = users.filter((user) => user.role === "admin").length;
  return (activeTab === "users" && role === "admin" && (
          <div key={`users-${tabAnimKey}`} className={`rounded-3xl p-6 md:p-8 border space-y-6 sv-tab-transition ${surfaceCard}`}>
            <h2 className={`text-2xl font-extrabold ${headingColor}`}>
              Role-Based Access Control (RBAC)
            </h2>
            <form onSubmit={handleCreateUser} className={`grid grid-cols-1 sm:grid-cols-4 gap-3 p-4 rounded-2xl border ${subSurfaceCard}`}>
              <input
                type="text"
                placeholder="New Operator Username"
                value={newUsername}
                onChange={(e) => setNewUsername(e.target.value)}
                className={`px-3.5 py-2 rounded-xl border text-sm ${darkMode ? "bg-[#15082E] border-white/15 text-white" : "bg-white border-slate-200"}`}
                required
              />
              <input
                type="password"
                placeholder="Temporary Password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                className={`px-3.5 py-2 rounded-xl border text-sm ${darkMode ? "bg-[#15082E] border-white/15 text-white" : "bg-white border-slate-200"}`}
                required
              />
              <select
                value={newRole}
                onChange={(e) => setNewRole(e.target.value)}
                className={`px-3.5 py-2 rounded-xl border text-sm ${darkMode ? "bg-[#15082E] border-white/15 text-white" : "bg-white border-slate-200"}`}
              >
                <option value="admin">Admin (Full Control)</option>
                <option value="analyst">Analyst (Triage & Scan)</option>
                <option value="viewer">Viewer (Read-Only Audit)</option>
              </select>
              <button
                type="submit"
                className="px-4 py-2 rounded-xl bg-gradient-to-r from-[#8121D7] to-[#00B89E] text-white font-bold text-xs cursor-pointer"
              >
                + Provision Operator
              </button>
            </form>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              {users.map((u, idx) => (
                <UserCard
                  key={`${u.id}-${u.role}`}
                  user={u}
                  currentUser={currentUser}
                  adminCount={adminCount}
                  darkMode={darkMode}
                  headingColor={headingColor}
                  mutedText={mutedText}
                  subSurfaceCard={subSurfaceCard}
                  onRoleChange={handleUpdateUserRole}
                  onPasswordReset={handleResetUserPassword}
                  onDelete={handleDeleteUser}
                  animationDelay={`${idx * 0.06}s`}
                />
              ))}
            </div>
          </div>
        ));
}
