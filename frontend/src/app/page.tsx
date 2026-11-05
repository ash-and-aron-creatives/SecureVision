"use client";
import { useState, useEffect } from "react";
import { SecureApp } from "./SecureApp";

export default function LandingFlow() {
  const [stage, setStage] = useState("splash"); // 'splash', 'landing', 'app'
  const [activeDropdown, setActiveDropdown] = useState<string | null>(null);
  const [searchOpen, setSearchOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [mobileNavOpen, setMobileNavOpen] = useState(false);

  useEffect(() => {
    if (stage === "splash") {
      const timer = setTimeout(() => setStage("landing"), 900);
      return () => clearTimeout(timer);
    }
  }, [stage]);

  if (stage === "app") return <SecureApp onBackToHome={() => setStage("landing")} />;

  const scrollToSection = (id: string) => {
    setActiveDropdown(null);
    const el = document.getElementById(id);
    if (el) {
      el.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  };

  const navMenus: Record<string, { id: string; items: { title: string; desc: string; badge: string }[] }> = {
    Platform: {
      id: "platform",
      items: [
        { title: "Backend Scoring Engine", desc: "One auditable scorer returns the priority tier, score, and rationale.", badge: "CORE" },
        { title: "CSV Finding Import", desc: "Validate vulnerability CSVs and map findings to assets.", badge: "INGEST" },
        { title: "Asset Context Correlation", desc: "Weight CVEs by internet exposure, data sensitivity, and criticality.", badge: "CONTEXT" },
      ],
    },
    Solutions: {
      id: "solutions",
      items: [
        { title: "Exploit-Led Remediation", desc: "Prioritize findings using exploit status, threat likelihood, and asset context.", badge: "SECOPS" },
        { title: "Executive & Audit Compliance", desc: "Generate cryptographically verifiable PDF/CSV triage trails.", badge: "GRC" },
        { title: "Role-Based Team Workflows", desc: "Granular JWT RBAC for Admins, Analysts, and Read-Only Auditors.", badge: "RBAC" },
      ],
    },
    Resources: {
      id: "resources",
      items: [
        { title: "Scoring Formula Whitepaper", desc: "Deep dive into CVSS + EPSS + KEV + Asset Criticality math.", badge: "DOCS" },
        { title: "REST API & Webhook Specs", desc: "Automate scan uploads and Jira ticket creation via FastAPI.", badge: "API" },
        { title: "Sample Vulnerability Datasets", desc: "Use scanner exports to evaluate findings with backend asset and threat context.", badge: "DATA" },
      ],
    },
    Company: {
      id: "company",
      items: [
        { title: "Our Mission", desc: "Eliminating alert fatigue for modern security operations centers.", badge: "ABOUT" },
        { title: "Security & Architecture", desc: "Built on zero-trust principles with full audit log immutability.", badge: "TRUST" },
        { title: "Book a Walkthrough", desc: "See how SecureVision prioritizes findings using threat and asset context.", badge: "DEMO" },
      ],
    },
  };

  // STAGE 1: Motion UI Splash Screen
  if (stage === "splash") {
    return (
      <div className="min-h-screen flex flex-col items-center justify-center bg-gradient-to-br from-[#2B125A] via-[#1D0B43] to-[#0D0322] overflow-hidden relative">
        <style>{`
          @keyframes letterDance {
            0%, 100% { transform: translateY(0px) scale(1); }
            50% { transform: translateY(-14px) scale(1.04); filter: drop-shadow(0 12px 20px rgba(0, 229, 196, 0.45)); }
          }
          @keyframes logoFloat {
            0%, 100% { transform: translateY(0px) rotate(0deg) scale(1); }
            50% { transform: translateY(-10px) rotate(2deg) scale(1.06); filter: drop-shadow(0 0 28px rgba(0, 229, 196, 0.6)); }
          }
          @keyframes waveUndulate1 {
            0%, 100% { transform: translateX(0px) translateY(0px) scaleY(1); }
            50% { transform: translateX(-35px) translateY(-18px) scaleY(1.12); }
          }
          @keyframes waveUndulate2 {
            0%, 100% { transform: translateX(0px) translateY(0px) scaleY(1); }
            50% { transform: translateX(35px) translateY(14px) scaleY(0.9); }
          }
          .dance-char {
            display: inline-block;
            animation: letterDance 1.5s ease-in-out infinite;
          }
          .logo-float {
            animation: logoFloat 2.4s ease-in-out infinite;
          }
          .wave-motion-1 {
            animation: waveUndulate1 4s ease-in-out infinite;
          }
          .wave-motion-2 {
            animation: waveUndulate2 5s ease-in-out infinite;
          }
        `}</style>

        <div className="absolute w-[650px] h-[650px] bg-[#8121D7]/25 blur-[140px] rounded-full pointer-events-none"></div>
        <div className="absolute w-[450px] h-[450px] bg-[#00E5C4]/15 blur-[120px] rounded-full -top-20 -left-20 pointer-events-none"></div>

        <div className="z-10 flex flex-col items-center -mt-12">
          <div className="flex items-center gap-4 md:gap-5 mb-5">
            <svg viewBox="0 0 120 100" className="w-20 h-16 md:w-24 md:h-20 logo-float" fill="none" xmlns="http://www.w3.org/2000/svg">
              <defs>
                <linearGradient id="splashWingTop" x1="6" y1="20" x2="100" y2="80" gradientUnits="userSpaceOnUse">
                  <stop offset="0%" stopColor="#00E5C4"/>
                  <stop offset="55%" stopColor="#3B82F6"/>
                  <stop offset="100%" stopColor="#8121D7"/>
                </linearGradient>
                <linearGradient id="splashShieldGuard" x1="22" y1="35" x2="105" y2="95" gradientUnits="userSpaceOnUse">
                  <stop offset="0%" stopColor="#00E5C4"/>
                  <stop offset="45%" stopColor="#6D28D9"/>
                  <stop offset="100%" stopColor="#3B096C"/>
                </linearGradient>
                <linearGradient id="splashInnerBevel" x1="50" y1="20" x2="88" y2="75" gradientUnits="userSpaceOnUse">
                  <stop offset="0%" stopColor="#A5F3FC"/>
                  <stop offset="100%" stopColor="#00E5C4"/>
                </linearGradient>
              </defs>
              <path d="M 22 40 L 42 40 C 50 40 55 46 59 56 L 73 88 L 93 34 C 96 58 87 82 73 96 C 55 82 45 62 39 50 L 28 50 Z" fill="url(#splashShieldGuard)" />
              <path d="M 6 22 L 56 22 C 66 22 72 28 75 36 L 73 66 L 94 20 L 106 20 L 73 86 L 56 46 C 52 36 46 32 36 32 L 14 32 Z" fill="url(#splashWingTop)" />
              <path d="M 52 22 C 68 15 84 15 94 20 L 87 34 C 78 29 66 29 58 33 Z" fill="url(#splashInnerBevel)" opacity="0.85" />
            </svg>

            <h1 className="text-5xl md:text-7xl font-extrabold tracking-tight flex items-center select-none">
              {"Secure".split("").map((char, i) => (
                <span key={`sec-${i}`} className="dance-char text-white" style={{ animationDelay: `${i * 0.08}s` }}>
                  {char}
                </span>
              ))}
              {"Vision".split("").map((char, i) => (
                <span key={`vis-${i}`} className="dance-char text-[#00E5C4]" style={{ animationDelay: `${(i + 6) * 0.08}s` }}>
                  {char}
                </span>
              ))}
            </h1>
          </div>

          <div className="h-1.5 w-32 bg-gradient-to-r from-[#8121D7] via-[#00E5C4] to-[#1ABDD6] rounded-full animate-pulse shadow-[0_0_20px_#00E5C4]"></div>
        </div>

        <div className="absolute bottom-0 left-0 w-full h-[340px] overflow-hidden pointer-events-none z-0">
          <svg className="w-[115%] -left-[7.5%] h-full absolute bottom-0" viewBox="0 0 1440 340" preserveAspectRatio="none">
            <defs>
              <linearGradient id="waveCyan" x1="0%" y1="0%" x2="100%" y2="0%">
                <stop offset="0%" stopColor="rgba(129, 33, 215, 0.1)" />
                <stop offset="50%" stopColor="rgba(0, 229, 196, 0.65)" />
                <stop offset="100%" stopColor="rgba(229, 0, 125, 0.25)" />
              </linearGradient>
              <linearGradient id="wavePurple" x1="0%" y1="0%" x2="100%" y2="0%">
                <stop offset="0%" stopColor="rgba(0, 229, 196, 0.15)" />
                <stop offset="50%" stopColor="rgba(168, 85, 247, 0.6)" />
                <stop offset="100%" stopColor="rgba(0, 229, 196, 0.2)" />
              </linearGradient>
              <filter id="nodeGlow">
                <feGaussianBlur stdDeviation="4" result="coloredBlur"/>
                <feMerge>
                  <feMergeNode in="coloredBlur"/>
                  <feMergeNode in="SourceGraphic"/>
                </feMerge>
              </filter>
            </defs>

            <g className="wave-motion-1">
              <path d="M-100,320 C250,150 650,280 1540,120" fill="none" stroke="url(#waveCyan)" strokeWidth="2.5" />
              <path d="M-100,280 C350,180 800,330 1540,180" fill="none" stroke="url(#wavePurple)" strokeWidth="2" />
              <path d="M-100,340 C450,220 900,140 1540,260" fill="none" stroke="rgba(255,255,255,0.18)" strokeWidth="1.5" />
              <circle cx="380" cy="215" r="5" fill="#fff" filter="url(#nodeGlow)" className="animate-ping" />
              <circle cx="380" cy="215" r="4" fill="#00E5C4" filter="url(#nodeGlow)" />
              <circle cx="960" cy="205" r="5" fill="#fff" filter="url(#nodeGlow)" />
            </g>

            <g className="wave-motion-2">
              <path d="M-100,260 C300,340 750,120 1540,240" fill="none" stroke="url(#waveCyan)" strokeWidth="2" />
              <path d="M-100,330 C520,140 880,290 1540,150" fill="none" stroke="url(#wavePurple)" strokeWidth="2.5" />
              <path d="M-100,300 C200,240 600,190 1540,310" fill="none" stroke="rgba(0,229,196,0.22)" strokeWidth="1" />
              <circle cx="670" cy="218" r="5" fill="#fff" filter="url(#nodeGlow)" />
              <circle cx="820" cy="238" r="4" fill="#E5007D" filter="url(#nodeGlow)" className="animate-pulse" />
              <circle cx="1120" cy="202" r="4" fill="#00E5C4" filter="url(#nodeGlow)" />
            </g>
          </svg>
        </div>
      </div>
    );
  }

  // STAGE 2: Quantexa-Style Enterprise Landing Page with Interactive Header & Scrollable Sections
  return (
    <div className="min-h-screen bg-gradient-to-br from-[#4C2396] via-[#2F1366] to-[#120524] text-white font-sans overflow-x-hidden scroll-smooth">
      {/* Sticky Enterprise Header */}
      <nav 
        onMouseLeave={() => setActiveDropdown(null)}
        className="flex items-center justify-between px-4 sm:px-8 py-3.5 sm:py-4 bg-gradient-to-r from-[#8121D7] to-[#1ABDD6] sticky top-0 z-50 shadow-xl relative"
      >
        <div 
          onClick={() => window.scrollTo({ top: 0, behavior: "smooth" })}
          className="flex items-center cursor-pointer hover:opacity-95 transition-opacity"
        >
          <svg viewBox="0 0 120 100" className="w-13 h-11 mr-2.5 drop-shadow-[0_2px_10px_rgba(0,229,196,0.3)]" fill="none" xmlns="http://www.w3.org/2000/svg">
            <defs>
              <linearGradient id="opt2WingTop" x1="6" y1="20" x2="100" y2="80" gradientUnits="userSpaceOnUse">
                <stop offset="0%" stopColor="#00E5C4"/>
                <stop offset="55%" stopColor="#3B82F6"/>
                <stop offset="100%" stopColor="#8121D7"/>
              </linearGradient>
              <linearGradient id="opt2ShieldGuard" x1="22" y1="35" x2="105" y2="95" gradientUnits="userSpaceOnUse">
                <stop offset="0%" stopColor="#00E5C4"/>
                <stop offset="45%" stopColor="#6D28D9"/>
                <stop offset="100%" stopColor="#3B096C"/>
              </linearGradient>
              <linearGradient id="opt2InnerBevel" x1="50" y1="20" x2="88" y2="75" gradientUnits="userSpaceOnUse">
                <stop offset="0%" stopColor="#A5F3FC"/>
                <stop offset="100%" stopColor="#00E5C4"/>
              </linearGradient>
            </defs>
            <path d="M 22 40 L 42 40 C 50 40 55 46 59 56 L 73 88 L 93 34 C 96 58 87 82 73 96 C 55 82 45 62 39 50 L 28 50 Z" fill="url(#opt2ShieldGuard)" />
            <path d="M 6 22 L 56 22 C 66 22 72 28 75 36 L 73 66 L 94 20 L 106 20 L 73 86 L 56 46 C 52 36 46 32 36 32 L 14 32 Z" fill="url(#opt2WingTop)" />
            <path d="M 52 22 C 68 15 84 15 94 20 L 87 34 C 78 29 66 29 58 33 Z" fill="url(#opt2InnerBevel)" opacity="0.85" />
          </svg>
          <span className="text-3xl text-white font-extrabold tracking-tight">Secure</span>
          <span className="text-3xl text-[#00E5C4] font-extrabold tracking-tight drop-shadow-sm">Vision</span>
        </div>

        {/* Interactive Nav Links with Dropdowns + Smooth Scroll */}
        <div className="hidden md:flex gap-8 text-sm font-semibold text-white/95 relative">
          {Object.keys(navMenus).map((label) => {
            const menu = navMenus[label];
            const isOpen = activeDropdown === label;
            return (
              <div
                key={label}
                onMouseEnter={() => setActiveDropdown(label)}
                className="relative py-2"
              >
                <button
                  onClick={() => scrollToSection(menu.id)}
                  className="hover:text-[#00E5C4] cursor-pointer transition-colors flex items-center gap-1.5 focus:outline-none"
                >
                  {label}
                  <svg
                    width="12"
                    height="12"
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="2.5"
                    className={`transition-transform duration-200 ${isOpen ? "rotate-180 text-[#00E5C4]" : ""}`}
                  >
                    <path d="M6 9l6 6 6-6" />
                  </svg>
                </button>

                {/* Dropdown Panel */}
                {isOpen && (
                  <div className="absolute left-0 top-full pt-2 w-80 z-50">
                    <div className="bg-[#1A0B3B]/95 backdrop-blur-2xl border border-white/15 rounded-xl p-3 shadow-2xl space-y-1">
                      {menu.items.map((item, idx) => (
                        <div
                          key={idx}
                          onClick={() => scrollToSection(menu.id)}
                          className="p-3 rounded-lg hover:bg-white/10 transition-colors cursor-pointer group"
                        >
                          <div className="flex items-center justify-between mb-1">
                            <span className="text-white font-bold text-xs group-hover:text-[#00E5C4] transition-colors">
                              {item.title}
                            </span>
                            <span className="text-[9px] font-bold px-1.5 py-0.5 rounded bg-[#00E5C4]/15 text-[#00E5C4] border border-[#00E5C4]/30">
                              {item.badge}
                            </span>
                          </div>
                          <p className="text-white/60 text-[11px] leading-snug">{item.desc}</p>
                        </div>
                      ))}
                      <div className="pt-2 mt-1 border-t border-white/10 px-3 py-1.5 flex justify-between items-center text-[11px] text-[#00E5C4] font-semibold cursor-pointer hover:underline"
                           onClick={() => scrollToSection(menu.id)}>
                        <span>Explore full {label} section</span>
                        <span>/</span>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>

        {/* Right Actions: Search + Log In */}
        <div className="flex items-center gap-4">
          {searchOpen ? (
            <div className="flex items-center bg-[#1A0B3B]/80 border border-white/25 rounded-md px-3 py-1.5">
              <input
                type="text"
                placeholder="Search CVE, rules, docs..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") scrollToSection("platform");
                }}
                className="bg-transparent text-white text-xs focus:outline-none w-40 placeholder-white/50"
                autoFocus
              />
              <button onClick={() => setSearchOpen(false)} className="text-white/60 hover:text-white text-xs ml-2">/</button>
            </div>
          ) : (
            <button
              onClick={() => setSearchOpen(true)}
              title="Search SecureVision"
              className="p-2 rounded-full hover:bg-white/10 transition-colors"
            >
              <svg className="w-5 h-5 text-white cursor-pointer hover:text-[#00E5C4] transition-colors" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"></path>
              </svg>
            </button>
          )}
          <button 
            onClick={() => setStage("app")}
            className="bg-[#93278F] hover:bg-[#B031AB] text-white px-4 sm:px-7 py-2 sm:py-2.5 rounded-sm text-xs sm:text-sm font-bold transition-all shadow-[0_4px_14px_0_rgba(147,39,143,0.39)] cursor-pointer"
          >
            Log In
          </button>
          <button
            type="button"
            onClick={() => setMobileNavOpen(!mobileNavOpen)}
            aria-label="Toggle Mobile Menu"
            className="md:hidden p-2 rounded-lg bg-white/15 text-white hover:bg-white/25"
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" strokeWidth="2.2" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" d="M4 6h16M4 12h16M4 18h16" />
            </svg>
          </button>
        </div>

        {/* Mobile / Tablet Dropdown Menu */}
        {mobileNavOpen && (
          <div className="md:hidden absolute top-full left-0 right-0 bg-[#1A0B3B]/98 backdrop-blur-2xl border-b border-white/15 p-4 space-y-2 z-50 shadow-2xl">
            {Object.keys(navMenus).map((label) => (
              <button
                key={label}
                onClick={() => {
                  setMobileNavOpen(false);
                  scrollToSection(navMenus[label].id);
                }}
                className="w-full text-left px-4 py-2.5 rounded-xl bg-white/5 hover:bg-white/10 text-sm font-bold text-white flex items-center justify-between"
              >
                <span>{label}</span>
                <span className="text-[#00E5C4]">-&gt;</span>
              </button>
            ))}
          </div>
        )}
      </nav>

      {/* HERO SECTION */}
      <main className="max-w-7xl mx-auto px-8 pt-20 pb-24 flex flex-col md:flex-row items-center relative">
        <div className="w-full md:w-3/5 z-10 animate-fade-in-up pr-8">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-white/10 border border-white/15 text-xs text-[#00E5C4] font-semibold mb-6">
            <span className="w-2 h-2 rounded-full bg-[#00E5C4] animate-ping"></span>
            Backend-Driven Vulnerability Prioritization
          </div>
          <h1 className="text-5xl md:text-7xl font-bold leading-tight mb-6 tracking-tight text-white">
            Fix the vulnerabilities<br/>attackers will<br/>actually use.
          </h1>
          <p className="text-lg md:text-xl text-white/75 mb-10 max-w-xl leading-relaxed">
            SecureVision joins your scanner, asset and threat data into one ranked queue, so your team spends this week on the findings that put the business at risk.
          </p>
          <div className="flex flex-wrap gap-4">
            <button 
              onClick={() => setStage("app")}
              className="bg-white text-[#1C0F4A] px-8 py-3.5 rounded text-sm font-bold hover:bg-[#00E5C4] transition-colors shadow-lg"
            >
              See our platform
            </button>
            <button 
              onClick={() => scrollToSection("platform")}
              className="bg-transparent border border-white/30 text-white px-8 py-3.5 rounded text-sm font-bold hover:bg-white/10 transition-colors"
            >
              Explore Architecture /
            </button>
          </div>
        </div>

        {/* Priority Queue Glassmorphism Card */}
        <div className="w-full md:w-2/5 mt-16 md:mt-0 relative animate-fade-in-up z-10" style={{ animationDelay: '0.2s' }}>
          <div className="bg-[#2D1B69]/45 backdrop-blur-xl border border-white/15 rounded-xl p-6 shadow-2xl relative z-10">
            <div className="flex justify-between items-end mb-6">
              <div>
                <h3 className="text-white font-semibold text-lg">Example priority queue</h3>
                <p className="text-white/50 text-xs">Illustrative preview — not live data</p>
              </div>
              <div className="text-right">
                <p className="text-white font-semibold text-sm">Sample findings</p>
              </div>
            </div>

            <div className="space-y-3">
              <div onClick={() => setStage("app")} className="bg-white/5 border border-white/10 rounded-lg p-4 flex justify-between items-center hover:bg-white/10 transition-colors cursor-pointer">
                <div>
                  <h4 className="text-white font-medium">CVE-2024-3400</h4>
                  <p className="text-white/60 text-xs mb-2">vpn-gw-01 / Palo Alto PAN-OS</p>
                  <div className="flex gap-2">
                    <span className="text-[10px] text-white/70 px-2 py-0.5 bg-[#FF4A4A]/20 border border-[#FF4A4A]/40 rounded">Exploited in the wild</span>
                    <span className="text-[10px] text-white/60 px-2 py-0.5 border border-white/20 rounded">Internet-facing</span>
                  </div>
                </div>
                <div className="flex flex-col items-end">
                  <span className="text-[#FF4A4A] font-bold text-sm">Critical</span>
                  <div className="w-8 h-1 bg-[#FF4A4A] rounded-full mt-1"></div>
                </div>
              </div>

              <div onClick={() => setStage("app")} className="bg-white/5 border border-white/10 rounded-lg p-4 flex justify-between items-center hover:bg-white/10 transition-colors cursor-pointer">
                <div>
                  <h4 className="text-white font-medium">CVE-2023-4966</h4>
                  <p className="text-white/60 text-xs mb-2">citrix-edge-02 / NetScaler ADC</p>
                  <div className="flex gap-2">
                    <span className="text-[10px] text-white/70 px-2 py-0.5 bg-[#FF4A4A]/20 border border-[#FF4A4A]/40 rounded">Exploited in the wild</span>
                    <span className="text-[10px] text-white/60 px-2 py-0.5 border border-white/20 rounded">Holds customer data</span>
                  </div>
                </div>
                <div className="flex flex-col items-end">
                  <span className="text-[#FF4A4A] font-bold text-sm">High</span>
                  <div className="w-8 h-1 bg-[#FF4A4A] rounded-full mt-1"></div>
                </div>
              </div>

              <div onClick={() => setStage("app")} className="bg-white/5 border border-white/10 rounded-lg p-4 flex justify-between items-center hover:bg-white/10 transition-colors cursor-pointer">
                <div>
                  <h4 className="text-white font-medium">CVE-2024-21762</h4>
                  <p className="text-white/60 text-xs mb-2">fw-hq-main / FortiOS SSL VPN</p>
                  <span className="text-[10px] text-white/60 px-2 py-0.5 border border-white/20 rounded">Public exploit code</span>
                </div>
                <div className="flex flex-col items-end">
                  <span className="text-[#FFB340] font-bold text-sm">Medium</span>
                  <div className="w-8 h-1 bg-[#FFB340] rounded-full mt-1"></div>
                </div>
              </div>

              <div onClick={() => setStage("app")} className="bg-white/5 border border-white/10 rounded-lg p-4 flex justify-between items-center hover:bg-white/10 transition-colors cursor-pointer">
                <div>
                  <h4 className="text-white font-medium">CVE-2023-38545</h4>
                  <p className="text-white/60 text-xs mb-2">build-runner-07 / curl libcurl</p>
                  <span className="text-[10px] text-white/60 px-2 py-0.5 border border-white/20 rounded">Internal only</span>
                </div>
                <div className="flex flex-col items-end">
                  <span className="text-[#00E5C4] font-bold text-sm">Low</span>
                  <div className="w-8 h-1 bg-[#00E5C4] rounded-full mt-1"></div>
                </div>
              </div>
            </div>
          </div>
          
          <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[120%] h-[120%] bg-[#5926B6]/20 blur-[100px] rounded-full -z-10 pointer-events-none"></div>
        </div>

        {/* Animated Data Lines in Hero Background */}
        <div className="absolute bottom-0 left-0 w-full overflow-hidden leading-none z-0 pointer-events-none h-[380px]">
          <svg className="absolute w-full h-full" viewBox="0 0 1200 400" preserveAspectRatio="none">
            <path className="animate-draw-line" d="M-100,300 C300,450 700,100 1300,250" fill="none" stroke="rgba(255,255,255,0.15)" strokeWidth="2" />
            <path className="animate-draw-line-reverse" d="M-100,350 C400,100 800,400 1300,200" fill="none" stroke="rgba(0,229,196,0.3)" strokeWidth="3" />
            <path className="animate-draw-line" d="M-100,200 C500,400 600,150 1300,300" fill="none" stroke="rgba(255,255,255,0.1)" strokeWidth="1" />
            <path className="animate-draw-line-reverse" d="M-100,250 C200,50 900,450 1300,150" fill="none" stroke="rgba(201,0,118,0.3)" strokeWidth="2" />
          </svg>
        </div>
      </main>

      {/* QUANTEXA-STYLE "INTEGRATED WITH / TRUSTED BY" GLASS BAR */}
      <div className="max-w-7xl mx-auto px-8 pb-20 relative z-10">
        <div className="bg-white/5 backdrop-blur-md border border-white/10 rounded-2xl py-6 px-8 flex flex-col items-center">
          <p className="text-[11px] uppercase tracking-[0.25em] text-white/50 font-semibold mb-5">
            SEAMLESS TELEMETRY & THREAT INTELLIGENCE INTEGRATION
          </p>
          <div className="grid grid-cols-2 md:grid-cols-6 gap-8 w-full text-center items-center opacity-80">
            <div className="font-bold text-sm tracking-wider text-white hover:text-[#00E5C4] transition-colors">CISA KEV</div>
            <div className="font-bold text-sm tracking-wider text-white hover:text-[#00E5C4] transition-colors">FIRST EPSS</div>
            <div className="font-bold text-sm tracking-wider text-white hover:text-[#00E5C4] transition-colors">NIST NVD</div>
            <div className="font-bold text-sm tracking-wider text-white hover:text-[#00E5C4] transition-colors">CSV FINDING IMPORTS</div>
            <div className="font-bold text-sm tracking-wider text-white hover:text-[#00E5C4] transition-colors">ASSET INVENTORY</div>
            <div className="font-bold text-sm tracking-wider text-white hover:text-[#00E5C4] transition-colors">AUDIT LOG</div>
          </div>
        </div>
      </div>

      {/* SECTION 1: PLATFORM */}
      <section id="platform" className="py-24 px-8 border-t border-white/10 bg-[#160730]/60 backdrop-blur-lg">
        <div className="max-w-7xl mx-auto">
          <div className="flex flex-col md:flex-row justify-between items-start md:items-end mb-14">
            <div>
              <span className="text-[#00E5C4] text-xs font-extrabold uppercase tracking-widest">01 / PLATFORM ARCHITECTURE</span>
              <h2 className="text-3xl md:text-5xl font-bold mt-2">Inside the Backend Scoring Engine</h2>
            </div>
            <p className="text-white/65 max-w-md text-sm mt-4 md:mt-0">
              The backend evaluates KEV status, EPSS, CVSS, Internet exposure, and asset criticality, then returns the priority tier, score, and structured rationale.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
            <div className="bg-[#25104C]/60 border border-white/10 rounded-2xl p-8 hover:border-[#00E5C4]/50 transition-all shadow-xl">
              <div className="w-12 h-12 rounded-xl bg-[#00E5C4]/15 border border-[#00E5C4]/30 flex items-center justify-center text-[#00E5C4] font-extrabold text-xl mb-6">
                01
              </div>
              <h3 className="text-xl font-bold mb-3">Multi-Scanner Normalization</h3>
              <p className="text-white/65 text-sm leading-relaxed mb-6">
                Import validated finding CSVs, deduplicate matching asset/CVE pairs, and map results to your asset inventory.
              </p>
              <div className="text-xs font-mono text-[#00E5C4] bg-black/30 p-3 rounded border border-white/5">
                POST /imports/commit
              </div>
            </div>

            <div className="bg-[#25104C]/60 border border-white/10 rounded-2xl p-8 hover:border-[#00E5C4]/50 transition-all shadow-xl">
              <div className="w-12 h-12 rounded-xl bg-[#8121D7]/25 border border-[#8121D7]/50 flex items-center justify-center text-[#E5007D] font-extrabold text-xl mb-6">
                02
              </div>
              <h3 className="text-xl font-bold mb-3">Threat and Asset Context</h3>
              <p className="text-white/65 text-sm leading-relaxed mb-6">
                A single backend scorer combines KEV, EPSS, CVSS, Internet exposure, and business criticality to rank each finding.
              </p>
              <div className="text-xs font-mono text-[#E5007D] bg-black/30 p-3 rounded border border-white/5">
                Score = backend(CVSS, KEV, EPSS, Exposure, Criticality)
              </div>
            </div>

            <div className="bg-[#25104C]/60 border border-white/10 rounded-2xl p-8 hover:border-[#00E5C4]/50 transition-all shadow-xl">
              <div className="w-12 h-12 rounded-xl bg-[#00E5C4]/15 border border-[#00E5C4]/30 flex items-center justify-center text-[#00E5C4] font-extrabold text-xl mb-6">
                03
              </div>
              <h3 className="text-xl font-bold mb-3">Explainable Triage Queue</h3>
              <p className="text-white/65 text-sm leading-relaxed mb-6">
                Every prioritized vulnerability includes the structured explanation returned by the backend, alongside its tier and score.
              </p>
              <div className="text-xs font-mono text-white/80 bg-black/30 p-3 rounded border border-white/5">
                Backend explanation: priority rationale and scoring inputs
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* SECTION 2: SOLUTIONS */}
      <section id="solutions" className="py-24 px-8 border-t border-white/10">
        <div className="max-w-7xl mx-auto">
          <div className="text-center max-w-3xl mx-auto mb-16">
            <span className="text-[#00E5C4] text-xs font-extrabold uppercase tracking-widest">02 / ENTERPRISE SOLUTIONS</span>
            <h2 className="text-3xl md:text-5xl font-bold mt-2 mb-4">Built for Every Security Stakeholder</h2>
            <p className="text-white/65 text-sm">
              From hands-on vulnerability analysts to compliance auditors, SecureVision aligns technical remediation with real business risk.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
            <div className="bg-gradient-to-br from-[#2D1B69]/70 to-[#1A0B3B]/70 border border-white/15 rounded-2xl p-8 flex flex-col justify-between">
              <div>
                <span className="px-3 py-1 text-[10px] font-bold uppercase bg-[#E5007D]/20 text-[#FF61D2] border border-[#E5007D]/40 rounded-full">
                  SecOps & Vulnerability Management
                </span>
                <h3 className="text-2xl font-bold mt-4 mb-3">Prioritize by Exploitability</h3>
                <p className="text-white/70 text-sm leading-relaxed mb-6">
                  Combine exploit status, threat likelihood, severity, and asset context to focus remediation on findings with the highest risk.
                </p>
              </div>
              <div className="grid grid-cols-3 gap-4 pt-6 border-t border-white/10 text-center">
                <div>
                  <p className="text-sm font-extrabold text-[#00E5C4]">Context-aware</p>
                  <p className="text-[11px] text-white/50">Risk prioritization</p>
                </div>
                <div>
                  <p className="text-2xl font-extrabold text-white">1</p>
                  <p className="text-[11px] text-white/50">Canonical Scorer</p>
                </div>
                <div>
                  <p className="text-sm font-extrabold text-[#FF4A4A]">Explainable</p>
                  <p className="text-[11px] text-white/50">Scoring rationale</p>
                </div>
              </div>
            </div>

            <div className="bg-gradient-to-br from-[#2D1B69]/70 to-[#1A0B3B]/70 border border-white/15 rounded-2xl p-8 flex flex-col justify-between">
              <div>
                <span className="px-3 py-1 text-[10px] font-bold uppercase bg-[#00E5C4]/20 text-[#00E5C4] border border-[#00E5C4]/40 rounded-full">
                  GRC, Audit & Executive Reporting
                </span>
                <h3 className="text-2xl font-bold mt-4 mb-3">Tamper-Evident Audit Trails & RBAC</h3>
                <p className="text-white/70 text-sm leading-relaxed mb-6">
                  Every scan upload, status change, asset modification, and user login is recorded in an immutable audit log. Enforce strict Role-Based Access Control (Admin, Analyst, Viewer) secured by JWT authentication.
                </p>
              </div>
              <div className="flex items-center justify-between pt-6 border-t border-white/10">
                <span className="text-xs text-white/60">ISO 27001 / SOC 2 / NIST CSF Aligned</span>
                <button
                  onClick={() => setStage("app")}
                  className="text-xs font-bold text-[#00E5C4] hover:underline"
                >
                  Launch RBAC Console /
                </button>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* SECTION 3: RESOURCES & SCORING TRANSPARENCY */}
      <section id="resources" className="py-24 px-8 border-t border-white/10 bg-[#160730]/60">
        <div className="max-w-7xl mx-auto">
          <div className="flex flex-col md:flex-row justify-between items-start md:items-end mb-14">
            <div>
              <span className="text-[#00E5C4] text-xs font-extrabold uppercase tracking-widest">03 / TECHNICAL RESOURCES</span>
              <h2 className="text-3xl md:text-5xl font-bold mt-2">Documentation & Scoring Specs</h2>
            </div>
            <button
              onClick={() => setStage("app")}
              className="mt-4 md:mt-0 bg-[#00E5C4] text-[#120524] px-6 py-2.5 rounded font-bold text-xs hover:bg-white transition-colors"
            >
              Test with Sample CSV in App /
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="bg-white/5 border border-white/10 rounded-xl p-6 flex flex-col justify-between hover:bg-white/10 transition-all">
              <div>
                <span className="text-[10px] font-mono uppercase px-2 py-1 bg-white/10 rounded text-[#00E5C4]">SPECIFICATION</span>
                <h4 className="text-lg font-bold mt-4 mb-2">Deterministic Prioritization Formula</h4>
                <p className="text-white/60 text-xs leading-relaxed">
                  Complete mathematical breakdown showing how base CVSS v3.1 combines with CISA Known Exploited Vulnerabilities (KEV) and asset business criticality tiers.
                </p>
              </div>
              <button onClick={() => setStage("app")} className="mt-6 text-left text-xs font-bold text-[#00E5C4] hover:underline">
                Inspect Rule Engine /
              </button>
            </div>

            <div className="bg-white/5 border border-white/10 rounded-xl p-6 flex flex-col justify-between hover:bg-white/10 transition-all">
              <div>
                <span className="text-[10px] font-mono uppercase px-2 py-1 bg-white/10 rounded text-[#FF61D2]">CSV SCHEMA</span>
                <h4 className="text-lg font-bold mt-4 mb-2">Bulk Scan Ingestion Guide</h4>
                <p className="text-white/60 text-xs leading-relaxed">
                  Standardized column headers (`cve_id`, `cvss_score`, `exploit_status`, `asset_name`, `exposure`) for one-click bulk CSV uploads into the SecureVision dashboard.
                </p>
              </div>
              <button onClick={() => setStage("app")} className="mt-6 text-left text-xs font-bold text-[#00E5C4] hover:underline">
                Open CSV Importer /
              </button>
            </div>

            <div className="bg-white/5 border border-white/10 rounded-xl p-6 flex flex-col justify-between hover:bg-white/10 transition-all">
              <div>
                <span className="text-[10px] font-mono uppercase px-2 py-1 bg-white/10 rounded text-[#FFB340]">SECURITY VERIFICATION</span>
                <h4 className="text-lg font-bold mt-4 mb-2">29/29 Automated Test Suite</h4>
                <p className="text-white/60 text-xs leading-relaxed">
                  Verified unit and integration test coverage across authentication, RBAC permission boundaries, deterministic rule evaluation, and audit logging.
                </p>
              </div>
              <button onClick={() => setStage("app")} className="mt-6 text-left text-xs font-bold text-[#00E5C4] hover:underline">
                Open Dashboard /
              </button>
            </div>
          </div>
        </div>
      </section>

      {/* SECTION 4: COMPANY & CTA FOOTER */}
      <section id="company" className="py-24 px-8 border-t border-white/10">
        <div className="max-w-5xl mx-auto text-center">
          <span className="text-[#00E5C4] text-xs font-extrabold uppercase tracking-widest">04 / ABOUT SECUREVISION</span>
          <h2 className="text-3xl md:text-5xl font-bold mt-3 mb-6">
            Decision Intelligence for Modern Cyber Defense
          </h2>
          <p className="text-white/70 text-base md:text-lg leading-relaxed mb-10 max-w-3xl mx-auto">
            SecureVision was engineered to bridge the gap between raw vulnerability scanners and executive risk decision-making/replacing guesswork with transparent, repeatable, and defensible prioritization.
          </p>
          <div className="flex flex-wrap justify-center gap-4">
            <button
              onClick={() => setStage("app")}
              className="bg-[#E5007D] hover:bg-[#FF1493] text-white px-10 py-4 rounded font-bold text-sm transition-all shadow-[0_0_25px_rgba(229,0,125,0.5)]"
            >
              Sign In to SecureVision Platform
            </button>
            <button
              onClick={() => window.scrollTo({ top: 0, behavior: "smooth" })}
              className="bg-white/10 hover:bg-white/20 border border-white/20 text-white px-8 py-4 rounded font-bold text-sm transition-all"
            >
              Back to Top /
            </button>
          </div>
        </div>
      </section>

      {/* Enterprise Footer */}
      <footer className="border-t border-white/10 bg-[#0D031A] py-8 px-8 text-xs text-white/50">
        <div className="max-w-7xl mx-auto flex flex-col md:flex-row justify-between items-center gap-4">
          <div className="flex items-center gap-2">
            <span className="text-white font-bold">Secure</span>
            <span className="text-[#00E5C4] font-bold">Vision</span>
            <span>/ Backend-Driven Vulnerability Prioritization Engine</span>
          </div>
          <div className="flex gap-6">
            <button onClick={() => scrollToSection("platform")} className="hover:text-white">Platform</button>
            <button onClick={() => scrollToSection("solutions")} className="hover:text-white">Solutions</button>
            <button onClick={() => scrollToSection("resources")} className="hover:text-white">Resources</button>
            <button onClick={() => scrollToSection("company")} className="hover:text-white">Company</button>
            <button onClick={() => setStage("app")} className="text-[#00E5C4] font-semibold hover:underline">Login</button>
          </div>
        </div>
      </footer>
    </div>
  );
}
