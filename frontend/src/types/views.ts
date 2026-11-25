import type { Dispatch, FormEventHandler, SetStateAction } from "react";
import type {
  Asset,
  AuditEntry,
  DashboardAnalytics,
  Finding,
  ImportPreview,
  MlWarmupState,
  PriorityMode,
  ScanResult,
  UserItem,
  UserRole,
} from "./index";

export interface LoginViewProps {
  onBackToHome?: () => void;
  error: string;
  username: string;
  setUsername: Dispatch<SetStateAction<string>>;
  password: string;
  setPassword: Dispatch<SetStateAction<string>>;
  showPassword: boolean;
  setShowPassword: Dispatch<SetStateAction<boolean>>;
  rememberMe: boolean;
  setRememberMe: Dispatch<SetStateAction<boolean>>;
  handleLogin: FormEventHandler<HTMLFormElement>;
}

export interface SecureAppViewProps {
  priorityMode: PriorityMode | null;
  mlWarmupState: MlWarmupState | null;
  activeTab: string;
  tabAnimKey: number;
  surfaceCard: string;
  headingColor: string;
  mutedText: string;
  switchTab: (tabId: string) => void;
  darkMode: boolean;
  exportExecutiveReport: () => void;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  subSurfaceCard: string;
  itemSurface: string;
  getTier: (finding: Finding) => "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN";
  analytics: DashboardAnalytics | null;
  weeklyBars: Array<{ day: string; height: string; label: string }>;
  completionPct: number | null;
  totalCount: number;
  resolvedCount: number;
  displayFindings: Finding[];
  setTierFilter: Dispatch<SetStateAction<string>>;
  tierFilter: string;
  exportPriorityCsv: () => void;
  filteredFindings: Finding[];
  toggleFindingStatus: (finding: Finding) => Promise<void>;
  handleCreateScan: FormEventHandler<HTMLFormElement>;
  handleLookupIntel: () => Promise<void>;
  intelMessage: string;
  isLookingUpIntel: boolean;
  scanCve: string;
  setScanCve: Dispatch<SetStateAction<string>>;
  scanAssetId: string;
  setScanAssetId: Dispatch<SetStateAction<string>>;
  assets: Asset[];
  scanCvss: string;
  setScanCvss: Dispatch<SetStateAction<string>>;
  scanEpss: string;
  setScanEpss: Dispatch<SetStateAction<string>>;
  scanKev: boolean;
  setScanKev: Dispatch<SetStateAction<boolean>>;
  scanResult: ScanResult | null;
  handleCsvPreview: FormEventHandler<HTMLFormElement>;
  setCsvFile: Dispatch<SetStateAction<File | null>>;
  createMissingAssets: boolean;
  setCreateMissingAssets: Dispatch<SetStateAction<boolean>>;
  dateOrder: "dmy" | "mdy";
  setDateOrder: Dispatch<SetStateAction<"dmy" | "mdy">>;
  setImportPreview: Dispatch<SetStateAction<ImportPreview | null>>;
  importPreview: ImportPreview | null;
  handleCsvCommit: () => Promise<void>;
  handleSaveAsset: FormEventHandler<HTMLFormElement>;
  handleEditAsset: (asset: Asset) => void;
  handleCancelAssetEdit: () => void;
  handleDeleteAsset: (asset: Asset) => Promise<void>;
  assetHost: string;
  setAssetHost: Dispatch<SetStateAction<string>>;
  assetType: string;
  setAssetType: Dispatch<SetStateAction<string>>;
  assetAddress: string;
  setAssetAddress: Dispatch<SetStateAction<string>>;
  assetOwner: string;
  setAssetOwner: Dispatch<SetStateAction<string>>;
  assetEnvironment: string;
  setAssetEnvironment: Dispatch<SetStateAction<string>>;
  assetExposure: string;
  setAssetExposure: Dispatch<SetStateAction<string>>;
  assetCrit: string;
  setAssetCrit: Dispatch<SetStateAction<string>>;
  editingAssetId: number | null;
  role: UserRole | "";
  currentUser: string;
  auditLogs: AuditEntry[];
  handleCreateUser: FormEventHandler<HTMLFormElement>;
  newUsername: string;
  setNewUsername: Dispatch<SetStateAction<string>>;
  newPassword: string;
  setNewPassword: Dispatch<SetStateAction<string>>;
  newRole: string;
  setNewRole: Dispatch<SetStateAction<string>>;
  users: UserItem[];
  handleUpdateUserRole: (userId: number, role: UserRole) => Promise<void>;
  handleResetUserPassword: (userId: number, password: string) => Promise<void>;
  handleDeleteUser: (user: UserItem) => Promise<void>;
  handleDeactivateUser: (user: UserItem) => Promise<void>;
  handleReactivateUser: (user: UserItem) => Promise<void>;
  selectedFinding: Finding | null;
  setSelectedFinding: Dispatch<SetStateAction<Finding | null>>;
}
