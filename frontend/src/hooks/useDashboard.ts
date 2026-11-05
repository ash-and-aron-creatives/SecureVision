import { useEffect, useState } from "react";
import type { Dispatch, SetStateAction } from "react";
import type { Finding } from "../types";

function getStoredSessionValue(key: string): string | null {
  if (typeof window === "undefined") return null;
  try {
    return sessionStorage.getItem(key);
  } catch {
    return null;
  }
}

function getStoredTheme(): string | null {
  if (typeof window === "undefined") return null;
  try {
    return localStorage.getItem("sv_theme");
  } catch {
    return null;
  }
}

export function useDashboard(setSelectedFinding: Dispatch<SetStateAction<Finding | null>>) {
  const [activeTab, setActiveTab] = useState<string>(() => {
    const savedTab = getStoredSessionValue("sv_view");
    return savedTab && ["dashboard", "queue", "scan", "import", "assets", "audit", "users"].includes(savedTab)
      ? savedTab
      : "dashboard";
  });
  const [tabAnimKey, setTabAnimKey] = useState<number>(0);
  const [darkMode, setDarkMode] = useState<boolean>(() => getStoredTheme() === "dark");
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [tierFilter, setTierFilter] = useState<string>("ALL");
  const [cmdOpen, setCmdOpen] = useState<boolean>(false);
  const [cmdQuery, setCmdQuery] = useState<string>("");
  const [mobileMenuOpen, setMobileMenuOpen] = useState<boolean>(false);

  const switchTab = (tabId: string) => {
    setActiveTab(tabId);
    setTabAnimKey((prev) => prev + 1);
    setMobileMenuOpen(false);
  };

  const toggleTheme = () => {
    setDarkMode((prev) => {
      const next = !prev;
      if (typeof window !== "undefined") {
        localStorage.setItem("sv_theme", next ? "dark" : "light");
      }
      return next;
    });
  };

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && (e.key.toLowerCase() === "k" || e.key.toLowerCase() === "f")) {
        e.preventDefault();
        setCmdOpen((prev) => !prev);
      } else if (e.key === "Escape") {
        setCmdOpen(false);
        setSelectedFinding(null);
        setMobileMenuOpen(false);
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [setSelectedFinding]);

  return {
    activeTab,
    setActiveTab,
    tabAnimKey,
    setTabAnimKey,
    darkMode,
    setDarkMode,
    searchQuery,
    setSearchQuery,
    tierFilter,
    setTierFilter,
    cmdOpen,
    setCmdOpen,
    cmdQuery,
    setCmdQuery,
    mobileMenuOpen,
    setMobileMenuOpen,
    switchTab,
    toggleTheme,
  };
}
