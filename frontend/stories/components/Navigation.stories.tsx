import type { Meta, StoryObj } from '@storybook/react';
import { Navigation, NavigationSection } from '@/components/ui/Navigation';
import {
  LayoutDashboard,
  Shield,
  Code,
  MessageSquare,
  FileText,
  Package,
  AlertTriangle,
  FileCode,
  Image,
  Activity,
  Container,
  FileWarning,
  Bell,
  AlertCircle,
  Users,
  TrendingUp,
  Webhook,
  Lock,
  Network,
  Server,
  Heart,
  Settings,
} from 'lucide-react';

const meta: Meta<typeof Navigation> = {
  title: 'Components/Navigation',
  component: Navigation,
  parameters: {
    layout: 'padded',
  },
  tags: ['autodocs'],
};

export default meta;
type Story = StoryObj<typeof Navigation>;

// DevSecOps Lifecycle Navigation (Production)
export const DevSecOpsLifecycle: Story = {
  args: {
    sections: [
      // Overview
      {
        id: 'overview',
        label: 'Overview',
        icon: LayoutDashboard,
        color: 'text-blue-600 dark:text-blue-400',
        items: [
          { name: 'Dashboard', href: '/', icon: LayoutDashboard },
          { name: 'Security Posture', href: '/security-posture', icon: Shield },
        ],
      },
      // Build
      {
        id: 'build',
        label: 'Build',
        icon: Code,
        color: 'text-yellow-600 dark:text-yellow-400',
        items: [
          { name: 'Code Quality', href: '/code-quality', icon: Code },
          { name: 'Developer Feedback', href: '/developer-feedback', icon: MessageSquare },
          { name: 'Policies', href: '/policies', icon: FileText },
        ],
      },
      // Deploy
      {
        id: 'deploy',
        label: 'Deploy',
        icon: Package,
        color: 'text-orange-600 dark:text-orange-400',
        items: [
          { name: 'Deployments', href: '/deployments', icon: Package },
          { name: 'Vulnerabilities', href: '/vulnerabilities', icon: AlertTriangle },
          { name: 'SBOMs', href: '/sboms', icon: FileCode },
          { name: 'Images', href: '/images', icon: Image },
        ],
      },
      // Run
      {
        id: 'run',
        label: 'Run',
        icon: Activity,
        color: 'text-red-600 dark:text-red-400',
        items: [
          { name: 'Runtime Security', href: '/runtime-security', icon: Activity },
          { name: 'Containers', href: '/containers', icon: Container },
          { name: 'Logs', href: '/logs', icon: FileWarning },
          { name: 'Alerts', href: '/alerts', icon: Bell },
        ],
      },
      // Govern
      {
        id: 'govern',
        label: 'Govern',
        icon: Shield,
        color: 'text-purple-600 dark:text-purple-400',
        items: [
          { name: 'Risk Exceptions', href: '/exceptions', icon: AlertCircle },
          { name: 'Teams & Ownership', href: '/teams', icon: Users },
          { name: 'Security Maturity', href: '/maturity', icon: TrendingUp },
          { name: 'Webhooks', href: '/webhooks', icon: Webhook },
        ],
      },
      // Platform
      {
        id: 'platform',
        label: 'Platform',
        icon: Settings,
        color: 'text-gray-600 dark:text-gray-400',
        items: [
          { name: 'Platform Security', href: '/platform-security', icon: Lock },
          { name: 'Networks', href: '/networks', icon: Network },
          { name: 'Proxies', href: '/proxies', icon: Server },
          { name: 'Health', href: '/health', icon: Heart },
          { name: 'Settings', href: '/settings', icon: Settings },
        ],
      },
    ],
  },
};

// With active state
export const WithActiveState: Story = {
  args: {
    sections: [
      {
        id: 'overview',
        label: 'Overview',
        icon: LayoutDashboard,
        color: 'text-blue-600 dark:text-blue-400',
        items: [
          { name: 'Dashboard', href: '/', icon: LayoutDashboard },
          { name: 'Security Posture', href: '/security-posture', icon: Shield },
        ],
      },
      {
        id: 'deploy',
        label: 'Deploy',
        icon: Package,
        color: 'text-orange-600 dark:text-orange-400',
        items: [
          { name: 'Deployments', href: '/deployments', icon: Package, current: true },
          { name: 'Vulnerabilities', href: '/vulnerabilities', icon: AlertTriangle },
        ],
      },
    ],
  },
};

// With badges
export const WithBadges: Story = {
  args: {
    sections: [
      {
        id: 'overview',
        label: 'Overview',
        icon: LayoutDashboard,
        color: 'text-blue-600 dark:text-blue-400',
        items: [
          { name: 'Dashboard', href: '/', icon: LayoutDashboard },
          {
            name: 'Security Posture',
            href: '/security-posture',
            icon: Shield,
            badge: (
              <span className="inline-flex items-center justify-center h-5 w-5 rounded-full bg-red-100 dark:bg-red-900/30 text-xs font-medium text-red-700 dark:text-red-400">
                3
              </span>
            ),
          },
        ],
      },
      {
        id: 'deploy',
        label: 'Deploy',
        icon: Package,
        color: 'text-orange-600 dark:text-orange-400',
        items: [
          { name: 'Deployments', href: '/deployments', icon: Package },
          {
            name: 'Vulnerabilities',
            href: '/vulnerabilities',
            icon: AlertTriangle,
            badge: (
              <span className="inline-flex items-center justify-center h-5 w-5 rounded-full bg-orange-100 dark:bg-orange-900/30 text-xs font-medium text-orange-700 dark:text-orange-400">
                12
              </span>
            ),
          },
        ],
      },
      {
        id: 'run',
        label: 'Run',
        icon: Activity,
        color: 'text-red-600 dark:text-red-400',
        items: [
          {
            name: 'Alerts',
            href: '/alerts',
            icon: Bell,
            badge: (
              <span className="inline-flex items-center justify-center px-2 py-0.5 rounded-full bg-red-100 dark:bg-red-900/30 text-xs font-medium text-red-700 dark:text-red-400">
                New
              </span>
            ),
          },
        ],
      },
    ],
  },
};

// Collapsible sections
export const CollapsibleSections: Story = {
  args: {
    sections: [
      {
        id: 'overview',
        label: 'Overview',
        icon: LayoutDashboard,
        color: 'text-blue-600 dark:text-blue-400',
        items: [
          { name: 'Dashboard', href: '/', icon: LayoutDashboard },
          { name: 'Security Posture', href: '/security-posture', icon: Shield },
        ],
      },
      {
        id: 'deploy',
        label: 'Deploy',
        icon: Package,
        color: 'text-orange-600 dark:text-orange-400',
        collapsible: true,
        items: [
          { name: 'Deployments', href: '/deployments', icon: Package },
          { name: 'Vulnerabilities', href: '/vulnerabilities', icon: AlertTriangle },
          { name: 'SBOMs', href: '/sboms', icon: FileCode },
          { name: 'Images', href: '/images', icon: Image },
        ],
      },
      {
        id: 'platform',
        label: 'Platform',
        icon: Settings,
        color: 'text-gray-600 dark:text-gray-400',
        collapsible: true,
        defaultCollapsed: true,
        items: [
          { name: 'Platform Security', href: '/platform-security', icon: Lock },
          { name: 'Networks', href: '/networks', icon: Network },
          { name: 'Settings', href: '/settings', icon: Settings },
        ],
      },
    ],
  },
};

// Minimal (no icons)
export const Minimal: Story = {
  args: {
    sections: [
      {
        id: 'main',
        label: 'Main',
        items: [
          { name: 'Dashboard', href: '/' },
          { name: 'Deployments', href: '/deployments' },
          { name: 'Vulnerabilities', href: '/vulnerabilities' },
        ],
      },
      {
        id: 'admin',
        label: 'Admin',
        items: [
          { name: 'Teams', href: '/teams' },
          { name: 'Settings', href: '/settings' },
        ],
      },
    ],
  },
};

// In sidebar layout
export const InSidebar: Story = {
  render: () => (
    <div className="flex h-screen bg-gray-50 dark:bg-gray-950">
      {/* Sidebar */}
      <div className="w-64 bg-white dark:bg-gray-900 border-r border-gray-200 dark:border-gray-800 p-4 overflow-y-auto">
        {/* Logo */}
        <div className="mb-8">
          <h1 className="text-xl font-bold text-gray-900 dark:text-white">
            InfraPilot
          </h1>
          <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
            DevSecOps Platform
          </p>
        </div>

        {/* Navigation */}
        <Navigation
          sections={[
            {
              id: 'overview',
              label: 'Overview',
              icon: LayoutDashboard,
              color: 'text-blue-600 dark:text-blue-400',
              items: [
                { name: 'Dashboard', href: '/', icon: LayoutDashboard, current: true },
                { name: 'Security Posture', href: '/security-posture', icon: Shield },
              ],
            },
            {
              id: 'build',
              label: 'Build',
              icon: Code,
              color: 'text-yellow-600 dark:text-yellow-400',
              items: [
                { name: 'Code Quality', href: '/code-quality', icon: Code },
                { name: 'Developer Feedback', href: '/developer-feedback', icon: MessageSquare },
                { name: 'Policies', href: '/policies', icon: FileText },
              ],
            },
            {
              id: 'deploy',
              label: 'Deploy',
              icon: Package,
              color: 'text-orange-600 dark:text-orange-400',
              items: [
                { name: 'Deployments', href: '/deployments', icon: Package },
                {
                  name: 'Vulnerabilities',
                  href: '/vulnerabilities',
                  icon: AlertTriangle,
                  badge: (
                    <span className="inline-flex items-center justify-center h-5 w-5 rounded-full bg-red-100 dark:bg-red-900/30 text-xs font-medium text-red-700 dark:text-red-400">
                      12
                    </span>
                  ),
                },
                { name: 'SBOMs', href: '/sboms', icon: FileCode },
              ],
            },
            {
              id: 'run',
              label: 'Run',
              icon: Activity,
              color: 'text-red-600 dark:text-red-400',
              items: [
                { name: 'Runtime Security', href: '/runtime-security', icon: Activity },
                { name: 'Containers', href: '/containers', icon: Container },
              ],
            },
            {
              id: 'govern',
              label: 'Govern',
              icon: Shield,
              color: 'text-purple-600 dark:text-purple-400',
              items: [
                { name: 'Risk Exceptions', href: '/exceptions', icon: AlertCircle },
                { name: 'Teams', href: '/teams', icon: Users },
              ],
            },
          ]}
        />
      </div>

      {/* Main content */}
      <div className="flex-1 overflow-y-auto p-8">
        <div className="max-w-7xl mx-auto">
          <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-4">
            Dashboard
          </h2>
          <p className="text-gray-600 dark:text-gray-400">
            Main content area
          </p>
        </div>
      </div>
    </div>
  ),
};

// Dark Mode
export const DarkMode: Story = {
  render: () => (
    <div className="dark">
      <div className="bg-gray-950 p-8 rounded-lg">
        <div className="w-64">
          <Navigation
            sections={[
              {
                id: 'overview',
                label: 'Overview',
                icon: LayoutDashboard,
                color: 'text-blue-400',
                items: [
                  { name: 'Dashboard', href: '/', icon: LayoutDashboard, current: true },
                  { name: 'Security Posture', href: '/security-posture', icon: Shield },
                ],
              },
              {
                id: 'deploy',
                label: 'Deploy',
                icon: Package,
                color: 'text-orange-400',
                items: [
                  { name: 'Deployments', href: '/deployments', icon: Package },
                  {
                    name: 'Vulnerabilities',
                    href: '/vulnerabilities',
                    icon: AlertTriangle,
                    badge: (
                      <span className="inline-flex items-center justify-center h-5 w-5 rounded-full bg-red-900/30 text-xs font-medium text-red-400">
                        12
                      </span>
                    ),
                  },
                ],
              },
              {
                id: 'govern',
                label: 'Govern',
                icon: Shield,
                color: 'text-purple-400',
                items: [
                  { name: 'Risk Exceptions', href: '/exceptions', icon: AlertCircle },
                  { name: 'Teams', href: '/teams', icon: Users },
                ],
              },
            ]}
          />
        </div>
      </div>
    </div>
  ),
  parameters: {
    backgrounds: { default: 'dark' },
  },
};
