"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import {
  LayoutDashboard,
  Container,
  Globe,
  FileText,
  Bell,
  Settings,
  LogOut,
  Users,
  Menu,
  X,
  Activity,
  Network,
  HardDrive,
  Image,
  Shield,
  ShieldCheck,
  Package,
  AlertTriangle,
  MessageSquare,
  ShieldAlert,
  Trophy,
  Code2,
  Gauge,
  Rocket,
  Play,
  Scale,
  Wrench,
  Box,
  Database,
  Key,
  Archive,
  BarChart3,
} from "lucide-react";
import { useState, useEffect } from "react";
import { useAuthStore } from "@/lib/auth";
import { cn, isIPAddress } from "@/lib/utils";
import { ThemeToggle } from "@/components/theme-toggle";
import { AlertBar } from "@/components/ui/alert-bar";
import { api } from "@/lib/api";
import { Navigation, NavigationSection } from "@/components/ui/Navigation";
import { CommandPalette } from "@/components/ui/CommandPalette";

// DevSecOps Lifecycle Navigation Structure
// Streamlined: ~32 items → ~16 visible items (intent-centric, not tool-centric)
const navigationSections: NavigationSection[] = [
  {
    id: "overview",
    label: "Overview",
    icon: Gauge,
    color: "text-blue-600 dark:text-blue-400",
    items: [
      { name: "Dashboard", href: "/", icon: LayoutDashboard },
      { name: "Security Posture", href: "/security", icon: Shield },
    ],
  },
  {
    id: "build",
    label: "Build",
    icon: Code2,
    color: "text-yellow-600 dark:text-yellow-400",
    items: [
      { name: "Code Quality", href: "/code-quality", icon: Code2 },
      { name: "Developer Feedback", href: "/feedback", icon: MessageSquare },
      { name: "Policies", href: "/policies", icon: FileText },
    ],
  },
  {
    id: "deploy",
    label: "Deploy",
    icon: Rocket,
    color: "text-orange-600 dark:text-orange-400",
    items: [
      { name: "Deployments", href: "/deployments", icon: Package },
      { name: "Artifacts", href: "/deploy/artifacts", icon: Box }, // Consolidated: Images, Scans, SBOMs, Registries
      { name: "Vulnerabilities", href: "/vulnerabilities", icon: AlertTriangle },
    ],
  },
  {
    id: "run",
    label: "Run",
    icon: Play,
    color: "text-red-600 dark:text-red-400",
    items: [
      { name: "Runtime Security", href: "/runtime-security", icon: ShieldCheck },
      { name: "Exposure", href: "/run/exposure", icon: Globe },
      { name: "Traffic", href: "/traffic", icon: Network }, // Single entry for traffic management
      { name: "Containers", href: "/containers", icon: Container },
      { name: "Logs", href: "/logs", icon: FileText },
      { name: "Alerts", href: "/alerts", icon: Bell },
    ],
  },
  {
    id: "data",
    label: "Data",
    icon: Database,
    color: "text-cyan-600 dark:text-cyan-400",
    items: [
      { name: "Databases", href: "/data/databases", icon: Database },
      { name: "Backups", href: "/data/backups", icon: Archive },
      { name: "Secrets", href: "/data/secrets", icon: Key },
    ],
  },
  {
    id: "govern",
    label: "Govern",
    icon: Scale,
    color: "text-purple-600 dark:text-purple-400",
    items: [
      { name: "Risk Exceptions", href: "/exceptions", icon: ShieldAlert },
      { name: "Teams & Ownership", href: "/ownership", icon: Users },
      { name: "Security Maturity", href: "/maturity", icon: Trophy },
      { name: "Dependencies", href: "/dependencies", icon: Globe },
    ],
  },
  {
    id: "platform",
    label: "Platform",
    icon: Wrench,
    color: "text-gray-600 dark:text-gray-400",
    items: [
      { name: "Platform Security", href: "/platform-security", icon: ShieldCheck },
      { name: "Background Jobs", href: "/platform/jobs", icon: Activity },
      { name: "Metrics & Reports", href: "/platform/metrics", icon: BarChart3 },
      { name: "Infrastructure", href: "/platform/infrastructure", icon: HardDrive }, // Consolidated: Proxies, Networks, Volumes, Health
      { name: "Users", href: "/users", icon: Users },
      { name: "Settings", href: "/settings", icon: Settings },
    ],
  },
];

export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const pathname = usePathname();
  const router = useRouter();
  const { user, logout, accessToken } = useAuthStore();
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [isChecking, setIsChecking] = useState(true);
  const [showDomainWarning, setShowDomainWarning] = useState(false);

  // Check if accessing via IP address
  useEffect(() => {
    const checkDomainAccess = async () => {
      // Check if we've already dismissed this warning
      const dismissed = localStorage.getItem("ip_warning_dismissed");
      if (dismissed) return;

      // Check if current hostname is an IP address
      const hostname = window.location.hostname;
      if (!isIPAddress(hostname)) return;

      // Check if domain is configured
      try {
        const domainSettings = await api.getInfraPilotDomain();
        // If no domain configured or accessing via IP instead of configured domain, show warning
        if (!domainSettings.domain) {
          setShowDomainWarning(true);
        }
      } catch {
        // If can't fetch settings, show warning (likely no domain configured)
        setShowDomainWarning(true);
      }
    };

    checkDomainAccess();
  }, []);

  const handleDismissWarning = () => {
    setShowDomainWarning(false);
    localStorage.setItem("ip_warning_dismissed", "true");
  };

  useEffect(() => {
    const validateAuth = async () => {
      // Check for token in localStorage
      const token = localStorage.getItem("access_token");
      if (!token && !accessToken) {
        router.replace("/login");
        return;
      }

      // Validate token with backend
      try {
        const response = await fetch("/api/v1/auth/me", {
          headers: {
            Authorization: `Bearer ${token || accessToken}`,
          },
        });

        if (!response.ok) {
          // Token is invalid - clear it and redirect to login
          localStorage.removeItem("access_token");
          router.replace("/login");
          return;
        }

        setIsChecking(false);
      } catch {
        // Network error or backend down - redirect to login
        localStorage.removeItem("access_token");
        router.replace("/login");
      }
    };

    validateAuth();
  }, [accessToken, router]);

  if (isChecking) {
    return (
      <div className="flex h-screen items-center justify-center bg-gray-100 dark:bg-gray-950">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-600"></div>
      </div>
    );
  }

  return (
    <div className="flex h-screen bg-gray-100 dark:bg-gray-950">
      {/* Mobile sidebar overlay */}
      {sidebarOpen && (
        <div
          className="fixed inset-0 bg-black/50 z-40 lg:hidden"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      {/* Sidebar */}
      <aside
        className={cn(
          "fixed lg:static inset-y-0 left-0 z-50 w-64 bg-white dark:bg-gray-900 border-r border-gray-200 dark:border-gray-800 flex flex-col transform transition-transform lg:transform-none",
          sidebarOpen ? "translate-x-0" : "-translate-x-full lg:translate-x-0"
        )}
      >
        <div className="p-6 flex items-center justify-between">
          <Link href="/" className="flex items-center gap-2">
            <img src="/logo.svg" alt="InfraPilot" className="h-8 w-8" />
            <span className="text-xl font-bold text-gray-900 dark:text-white">InfraPilot</span>
          </Link>
          <button
            onClick={() => setSidebarOpen(false)}
            className="lg:hidden p-2 text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-white"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        <nav className="flex-1 px-3 overflow-y-auto">
          <Navigation
            sections={navigationSections}
            onItemClick={() => setSidebarOpen(false)}
          />
        </nav>

        {/* Theme toggle */}
        <div className="px-4 py-3 border-t border-gray-200 dark:border-gray-800">
          <div className="flex items-center justify-between">
            <span className="text-xs text-gray-500 dark:text-gray-400">Theme</span>
            <ThemeToggle />
          </div>
        </div>

        <div className="p-4 border-t border-gray-200 dark:border-gray-800">
          <div className="flex items-center gap-3 px-3 py-2">
            <div className="w-8 h-8 rounded-full bg-primary-600 flex items-center justify-center text-sm font-medium text-white">
              {user?.email?.[0]?.toUpperCase() || "U"}
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-sm font-medium text-gray-900 dark:text-white truncate">
                {user?.email || "User"}
              </p>
              <p className="text-xs text-gray-500 capitalize">
                {user?.role || "viewer"}
              </p>
            </div>
            <button
              onClick={logout}
              className="p-2 text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-white rounded-lg hover:bg-gray-100 dark:hover:bg-gray-800"
            >
              <LogOut className="h-4 w-4" />
            </button>
          </div>
        </div>
      </aside>

      {/* Main content */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Mobile header */}
        <header className="lg:hidden flex items-center justify-between p-4 bg-white dark:bg-gray-900 border-b border-gray-200 dark:border-gray-800">
          <button
            onClick={() => setSidebarOpen(true)}
            className="p-2 text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-white rounded-lg hover:bg-gray-100 dark:hover:bg-gray-800"
          >
            <Menu className="h-6 w-6" />
          </button>
          <Link href="/" className="flex items-center gap-2">
            <img src="/logo.svg" alt="InfraPilot" className="h-6 w-6" />
            <span className="text-lg font-semibold text-gray-900 dark:text-white">InfraPilot</span>
          </Link>
          <div className="w-10" />
        </header>

        <main className="flex-1 overflow-hidden flex flex-col">
          {showDomainWarning && (
            <AlertBar
              variant="warning"
              message="You're accessing InfraPilot via IP address. Configure a domain for better security and SSL support."
              action={{ label: "Set Up Domain", href: "/settings" }}
              dismissible
              onDismiss={handleDismissWarning}
            />
          )}
          <div className="flex-1 overflow-auto p-4 lg:p-8">{children}</div>
        </main>
      </div>

      {/* Command Palette - accessible via Cmd+K or Ctrl+K */}
      <CommandPalette />
    </div>
  );
}
