import {
  ArrowUpRight,
  Check,
  FileText,
  GitBranch,
  Info,
  Moon,
  RefreshCw,
  Search,
  ShieldCheck,
  Sun,
  TriangleAlert,
  Upload,
  X,
  type LucideIcon,
} from "lucide-react";

export type IconName =
  | "shield"
  | "github"
  | "upload"
  | "file"
  | "search"
  | "sun"
  | "moon"
  | "check"
  | "refresh"
  | "alert"
  | "info"
  | "close"
  | "arrow";

const icons: Record<IconName, LucideIcon> = {
  shield: ShieldCheck,
  github: GitBranch,
  upload: Upload,
  file: FileText,
  search: Search,
  sun: Sun,
  moon: Moon,
  check: Check,
  refresh: RefreshCw,
  alert: TriangleAlert,
  info: Info,
  close: X,
  arrow: ArrowUpRight,
};

export function Icon({
  name,
  className = "h-4 w-4",
}: {
  name: IconName;
  className?: string;
}) {
  const LucideIcon = icons[name];
  return <LucideIcon className={className} strokeWidth={1.8} aria-hidden="true" />;
}
