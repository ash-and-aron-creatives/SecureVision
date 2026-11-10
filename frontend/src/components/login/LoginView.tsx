"use client";
import type { LoginViewProps } from "@/types/views";

export function LoginView(props: LoginViewProps) {
  const { onBackToHome, error, username, setUsername, password, setPassword, showPassword, setShowPassword, rememberMe, setRememberMe, handleLogin } = props;
  return (
      <div className="min-h-screen flex flex-col justify-between bg-gradient-to-br from-[#2B125A] via-[#1A0B3B] to-[#0B031D] text-white font-sans relative overflow-hidden">
        <div className="absolute w-[600px] h-[600px] bg-[#8121D7]/25 blur-[140px] rounded-full -top-32 -left-32 pointer-events-none"></div>
        <div className="absolute w-[500px] h-[500px] bg-[#00E5C4]/15 blur-[130px] rounded-full -bottom-24 -right-24 pointer-events-none"></div>

        <header className="w-full max-w-7xl mx-auto px-6 sm:px-8 pt-6 flex items-center justify-between z-20">
          <button
            type="button"
            onClick={() => onBackToHome && onBackToHome()}
            className="inline-flex items-center gap-2.5 px-4 py-2 rounded-lg bg-white/5 hover:bg-white/15 border border-white/15 text-sm font-semibold text-white/90 hover:text-[#00E5C4] transition-all backdrop-blur-md shadow-lg cursor-pointer group"
          >
            <svg className="w-4 h-4 transition-transform group-hover:-translate-x-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2.5" d="M15 19l-7-7 7-7" />
            </svg>
            Back to Home
          </button>

          <div className="hidden sm:flex items-center gap-2 text-xs text-white/60 bg-white/5 border border-white/10 px-3.5 py-1.5 rounded-full backdrop-blur-md">
            <span className="w-2 h-2 rounded-full bg-[#00E5C4] animate-pulse"></span>
            <span>Backend scoring enabled</span>
          </div>
        </header>

        <div className="flex-1 flex items-center justify-center px-4 py-8 z-20">
          <div className="w-full max-w-md bg-[#23114B]/65 backdrop-blur-2xl border border-white/15 rounded-2xl p-6 sm:p-8 shadow-[0_25px_70px_rgba(0,0,0,0.65)] relative">
            <div className="absolute top-0 left-10 right-10 h-[2px] bg-gradient-to-r from-transparent via-[#00E5C4] to-transparent"></div>

            <div
              onClick={() => onBackToHome && onBackToHome()}
              className="flex flex-col items-center mb-7 cursor-pointer group"
            >
              <svg viewBox="0 0 120 100" className="w-16 h-14 mb-2 drop-shadow-[0_4px_15px_rgba(0,229,196,0.35)] group-hover:scale-105 transition-transform" fill="none" xmlns="http://www.w3.org/2000/svg">
                <defs>
                  <linearGradient id="loginWingTop" x1="6" y1="20" x2="100" y2="80" gradientUnits="userSpaceOnUse">
                    <stop offset="0%" stopColor="#00E5C4"/>
                    <stop offset="55%" stopColor="#3B82F6"/>
                    <stop offset="100%" stopColor="#8121D7"/>
                  </linearGradient>
                  <linearGradient id="loginShieldGuard" x1="22" y1="35" x2="105" y2="95" gradientUnits="userSpaceOnUse">
                    <stop offset="0%" stopColor="#00E5C4"/>
                    <stop offset="45%" stopColor="#6D28D9"/>
                    <stop offset="100%" stopColor="#3B096C"/>
                  </linearGradient>
                  <linearGradient id="loginInnerBevel" x1="50" y1="20" x2="88" y2="75" gradientUnits="userSpaceOnUse">
                    <stop offset="0%" stopColor="#A5F3FC"/>
                    <stop offset="100%" stopColor="#00E5C4"/>
                  </linearGradient>
                </defs>
                <path d="M 22 40 L 42 40 C 50 40 55 46 59 56 L 73 88 L 93 34 C 96 58 87 82 73 96 C 55 82 45 62 39 50 L 28 50 Z" fill="url(#loginShieldGuard)" />
                <path d="M 6 22 L 56 22 C 66 22 72 28 75 36 L 73 66 L 94 20 L 106 20 L 73 86 L 56 46 C 52 36 46 32 36 32 L 14 32 Z" fill="url(#loginWingTop)" />
                <path d="M 52 22 C 68 15 84 15 94 20 L 87 34 C 78 29 66 29 58 33 Z" fill="url(#loginInnerBevel)" opacity="0.85" />
              </svg>
              <div className="text-3xl font-extrabold tracking-tight flex items-center">
                <span className="text-white">Secure</span>
                <span className="text-[#00E5C4]">Vision</span>
              </div>
              <p className="text-xs text-white/60 mt-1.5 text-center">
                Decision Intelligence & Vulnerability Triage Portal
              </p>
            </div>

            {error && (
              <div className="mb-5 p-3.5 rounded-lg bg-[#FF4A4A]/15 border border-[#FF4A4A]/40 text-[#FF8080] text-xs flex items-center gap-2.5">
                <span>{error}</span>
              </div>
            )}

            <form onSubmit={handleLogin} className="space-y-4">
              <div>
                <label className="block text-xs font-semibold uppercase tracking-wider text-white/75 mb-1.5">
                  Operator Username
                </label>
                <input
                  type="text"
                  placeholder="Enter username"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  className="w-full px-4 py-3 rounded-lg bg-[#12072B]/80 border border-white/15 text-white placeholder-white/35 text-sm focus:outline-none focus:border-[#00E5C4]"
                  required
                />
              </div>

              <div>
                <label className="block text-xs font-semibold uppercase tracking-wider text-white/75 mb-1.5">
                  Password
                </label>
                <div className="relative">
                  <input
                    type={showPassword ? "text" : "password"}
                    placeholder="Enter password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className="w-full px-4 py-3 rounded-lg bg-[#12072B]/80 border border-white/15 text-white placeholder-white/35 text-sm focus:outline-none focus:border-[#00E5C4]"
                    required
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute inset-y-0 right-0 pr-3.5 flex items-center text-white/45 hover:text-[#00E5C4] text-xs"
                  >
                    {showPassword ? "Hide" : "Show"}
                  </button>
                </div>
              </div>

              <div className="flex items-center justify-between text-xs text-white/65 pt-1">
                <label className="flex items-center gap-2 cursor-pointer select-none">
                  <input
                    type="checkbox"
                    checked={rememberMe}
                    onChange={(e) => setRememberMe(e.target.checked)}
                    className="rounded border-white/20 bg-[#12072B] text-[#00E5C4]"
                  />
                  <span>Remember session (JWT)</span>
                </label>
                <span className="text-[#00E5C4]/90 font-medium">RBAC Enforced</span>
              </div>

              <button
                type="submit"
                className="w-full py-3.5 rounded-lg bg-gradient-to-r from-[#8121D7] via-[#93278F] to-[#1ABDD6] hover:opacity-95 text-white font-bold text-sm tracking-wide shadow-[0_0_25px_rgba(0,229,196,0.3)] transition-all cursor-pointer mt-2"
              >
                Sign In to Console
              </button>
            </form>

            {process.env.NEXT_PUBLIC_DEMO_MODE === "true" && (
              <p className="mt-5 text-center text-[11px] font-semibold text-amber-200/90">
                SYNTHETIC DEMO DATA — not real assets or findings
              </p>
            )}
          </div>
        </div>
      </div>
    );
}
