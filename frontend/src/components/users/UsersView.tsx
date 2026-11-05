"use client";
import type { SecureAppViewProps } from "@/types/views";

export function UsersView(props: SecureAppViewProps) {
  const {
    activeTab, tabAnimKey, surfaceCard, headingColor, mutedText,
    darkMode, subSurfaceCard, role, handleCreateUser, newUsername,
    setNewUsername, newPassword, setNewPassword, newRole, setNewRole,
    users,
  } = props;
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
                <div
                  key={u.id}
                  style={{ animationDelay: `${idx * 0.06}s` }}
                  className={`sv-card-pop p-5 rounded-2xl border hover:-translate-y-1 transition-all flex items-center justify-between ${subSurfaceCard}`}
                >
                  <div className="flex items-center gap-3">
                    <div className="w-9 h-9 rounded-full bg-gradient-to-tr from-[#8121D7] to-[#00E5C4] text-white font-bold text-xs flex items-center justify-center">
                      {u.username.slice(0, 2).toUpperCase()}
                    </div>
                    <div>
                      <p className={`font-bold text-sm ${headingColor}`}>{u.username}</p>
                      <p className={`text-[11px] ${mutedText}`}>JWT Authenticated</p>
                    </div>
                  </div>
                  <span className="px-2.5 py-1 rounded-full text-[11px] font-extrabold uppercase bg-[#8121D7]/15 text-[#8121D7] dark:text-[#00E5C4]">
                    {u.role}
                  </span>
                </div>
              ))}
            </div>
          </div>
        ));
}
