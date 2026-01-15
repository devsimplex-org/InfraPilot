"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { LogOut, X, Menu } from "lucide-react";
import { useState, useEffect } from "react";
import { useAuthStore } from "@/lib/auth";
import { cn, isIPAddress } from "@/lib/utils";
import { ThemeToggle } from "@/components/theme-toggle";
import { AlertBar } from "@/components/ui/alert-bar";
import { api } from "@/lib/api";
import { Navigation, type NavigationSection } from "@/components/ui/Navigation";
import {
  LayoutDashboard,
  Shield,
  ShieldCheck,
  Activity,
  Trophy,
  Code2,
  MessageSquare,
  Package,
  ShieldAlert,
  AlertTriangle,
  FileCode,
  Container,
  FileText,
  Bell,
  Network,
  HardDrive,
  Image as ImageIcon,
  Globe,
  Users,
  Settings,
  Webhook,
} from "lucide-react";

// DevSecOps lifecycle navigation structure
const navigationSections: NavigationSection[] = [
  // Overview (Executive & Entry Point)
  {
    id: "overview",
    label: "Overview",
    color: "blue",
    defaultCollapsed: false,
    items: [
      {
        name: "Dashboard",
        href: "/",
        icon: LayoutDashboard,
        description: "Are we safe? Overview of security and operations",
      },
      {
        name: "Security Dashboard",
        href: "/security",
        icon: Shield,
        description: "Comprehensive security overview",
      },
      {
        name: "Health",
        href: "/health",
        icon: Activity,
        description: "System health and status",
      },
    ],
  },

  // Build (Shift Left – Developers)
  {
    id: "build",
    label: "Build",
    color: "yellow",
    description: "Shift Left – Developer Security",
    defaultCollapsed: false,
    items: [
      {
        name: "Code Quality",
        href: "/code-quality",
        icon: Code2,
        description: "Code analysis and quality metrics",
      },
      {
        name: "Developer Feedback",
        href: "/feedback",
        icon: MessageSquare,
        description: "Real-time security feedback for developers",
      },
      {
        name: "Policies",
        href: "/policies",
        icon: FileText,
        description: "Security policies and rules",
        badge: { label: "Rego", variant: "default" },
      },
    ],
  },

  // Deploy (Release & Supply Chain) - Deployments is PRIMARY
  {
    id: "deploy",
    label: "Deploy",
    color: "orange",
    description: "Release & Supply Chain",
    defaultCollapsed: false,
    items: [
      {
        name: "Deployments",
        href: "/deployments",
        icon: ShieldCheck,
        description: "PRIMARY: Track and secure all deployments",
        badge: { label: "Primary", variant: "default" },
      },
      {
        name: "Vulnerabilities",
        href: "/vulnerabilities",
        icon: AlertTriangle,
        description: "Security vulnerabilities across deployments",
      },
      {
        name: "SBOMs",
        href: "/sboms",
        icon: Package,
        description: "Software Bill of Materials",
      },
      {
        name: "Images",
        href: "/docker/images",
        icon: ImageIcon,
        description: "Container images and scan results",
      },
      {
        name: "Webhooks",
        href: "/webhooks",
        icon: Webhook,
        description: "CI/CD and Git integrations",
      },
    ],
  },

  // Run (Production Reality)
  {
    id: "run",
    label: "Run",
    color: "red",
    description: "Production Runtime",
    defaultCollapsed: false,
    items: [
      {
        name: "Runtime Security",
        href: "/runtime-security",
        icon: Activity,
        description: "Live security monitoring and drift detection",
      },
      {
        name: "Containers",
        href: "/containers",
        icon: Container,
        description: "Running containers and resources",
      },
      {
        name: "Proxies",
        href: "/proxies",
        icon: Globe,
        description: "Reverse proxy and routing",
      },
      {
        name: "Alerts",
        href: "/alerts",
        icon: Bell,
        description: "Security alerts and notifications",
      },
      {
        name: "Logs",
        href: "/logs",
        icon: FileText,
        description: "Application and system logs",
      },
    ],
  },

  // Govern (Control, Exceptions, Ownership)
  {
    id: "govern",
    label: "Govern",
    color: "purple",
    description: "Control & Ownership",
    defaultCollapsed: false,
    items: [
      {
        name: "Risk Exceptions",
        href: "/exceptions",
        icon: ShieldAlert,
        description: "Approved security exceptions",
      },
      {
        name: "Ownership & Teams",
        href: "/ownership",
        icon: Users,
        description: "Service ownership and team structure",
      },
      {
        name: "Security Maturity",
        href: "/maturity",
        icon: Trophy,
        description: "Track security posture improvements",
      },
      {
        name: "Platform Security",
        href: "/platform-security",
        icon: ShieldCheck,
        description: "Infrastructure security controls",
      },
    ],
  },

  // Platform (Infrastructure & Admin)
  {
    id: "platform",
    label: "Platform",
    color: "gray",
    description: "Infrastructure & Admin",
    defaultCollapsed: true,
    items: [
      {
        name: "Networks",
        href: "/docker/networks",
        icon: Network,
        description: "Docker networks",
      },
      {
        name: "Volumes",
        href: "/docker/volumes",
        icon: HardDrive,
        description: "Docker volumes and storage",
      },
      {
        name: "Users",
        href: "/users",
        icon: Users,
        description: "User management",
      },
      {
        name: "Settings",
        href: "/settings",
        icon: Settings,
        description: "System configuration",
      },
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
      const dismissed = localStorage.getItem("ip_warning_dismissed");
      if (dismissed) return;

      const hostname = window.location.hostname;
      if (!isIPAddress(hostname)) return;

      try {
        const domainSettings = await api.getInfraPilotDomain();
        if (!domainSettings.domain) {
          setShowDomainWarning(true);
        }
      } catch {
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
      const token = localStorage.getItem("access_token");
      if (!token && !accessToken) {
        router.replace("/login");
        return;
      }

      try {
        const response = await fetch("/api/v1/auth/me", {
          headers: {
            Authorization: `Bearer ${token || accessToken}`,
          },
        });

        if (!response.ok) {
          localStorage.removeItem("access_token");
          router.replace("/login");
          return;
        }

        setIsChecking(false);
      } catch {
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
        {/* Logo */}
        <div className="p-6 flex items-center justify-between flex-shrink-0">
          <Link href="/" className="flex items-center gap-2">
            <img src="/logo.svg" alt="InfraPilot" className="h-8 w-8" />
            <span className="text-xl font-bold text-gray-900 dark:text-white">
              InfraPilot
            </span>
          </Link>
          <button
            onClick={() => setSidebarOpen(false)}
            className="lg:hidden p-2 text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-white"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Navigation */}
        <div className="flex-1 px-3 overflow-y-auto">
          <Navigation
            sections={navigationSections}
            onItemClick={() => setSidebarOpen(false)}
          />
        </div>

        {/* Theme toggle */}
        <div className="px-4 py-3 border-t border-gray-200 dark:border-gray-800 flex-shrink-0">
          <div className="flex items-center justify-between">
            <span className="text-xs text-gray-500 dark:text-gray-400">Theme</span>
            <ThemeToggle />
          </div>
        </div>

        {/* User profile */}
        <div className="p-4 border-t border-gray-200 dark:border-gray-800 flex-shrink-0">
          <div className="flex items-center gap-3 px-3 py-2">
            <div className="w-8 h-8 rounded-full bg-primary-600 flex items-center justify-center text-sm font-medium text-white flex-shrink-0">
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
              className="p-2 text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-white rounded-lg hover:bg-gray-100 dark:hover:bg-gray-800 flex-shrink-0"
              aria-label="Log out"
            >
              <LogOut className="h-4 w-4" />
            </button>
          </div>
        </div>
      </aside>

      {/* Main content */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Mobile header */}
        <header className="lg:hidden flex items-center justify-between p-4 bg-white dark:bg-gray-900 border-b border-gray-200 dark:border-gray-800 flex-shrink-0">
          <button
            onClick={() => setSidebarOpen(true)}
            className="p-2 text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-white rounded-lg hover:bg-gray-100 dark:hover:bg-gray-800"
            aria-label="Open sidebar"
          >
            <Menu className="h-6 w-6" />
          </button>
          <Link href="/" className="flex items-center gap-2">
            <img src="/logo.svg" alt="InfraPilot" className="h-6 w-6" />
            <span className="text-lg font-semibold text-gray-900 dark:text-white">
              InfraPilot
            </span>
          </Link>
          <div className="w-10" />
        </header>

        {/* Main content area */}
        <main className="flex-1 overflow-hidden flex flex-col">
          {showDomainWarning && (
            <AlertBar
              variant="warning"
              message="You're accessing InfraPilot via IP address. Configure a domain for better security and SSL support."
              action={{ label: "Set Up Domain", href: "/proxies" }}
              dismissible
              onDismiss={handleDismissWarning}
            />
          )}
          <div className="flex-1 overflow-auto p-4 lg:p-8">{children}</div>
        </main>
      </div>
    </div>
  );
}
