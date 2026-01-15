import type { Meta, StoryObj } from '@storybook/react';
import { PageHeader } from '@/components/ui/PageHeader';
import { Plus, RefreshCw, Download, Settings } from 'lucide-react';

const meta: Meta<typeof PageHeader> = {
  title: 'Components/PageHeader',
  component: PageHeader,
  parameters: {
    layout: 'padded',
  },
  tags: ['autodocs'],
};

export default meta;
type Story = StoryObj<typeof PageHeader>;

// Basic
export const Default: Story = {
  args: {
    title: 'Page Title',
    description: 'This is a description of what this page is about.',
  },
};

// With action button
export const WithAction: Story = {
  args: {
    title: 'Deployments',
    description: 'Manage and monitor your application deployments.',
    action: (
      <button className="inline-flex items-center gap-2 px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700">
        <Plus className="h-4 w-4" />
        New Deployment
      </button>
    ),
  },
};

// With multiple actions
export const WithMultipleActions: Story = {
  args: {
    title: 'Vulnerabilities',
    description: 'View and manage security vulnerabilities across your deployments.',
    action: (
      <div className="flex gap-2">
        <button className="inline-flex items-center gap-2 px-4 py-2 bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-200 dark:hover:bg-gray-700">
          <RefreshCw className="h-4 w-4" />
          Refresh
        </button>
        <button className="inline-flex items-center gap-2 px-4 py-2 bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-200 dark:hover:bg-gray-700">
          <Download className="h-4 w-4" />
          Export
        </button>
        <button className="inline-flex items-center gap-2 px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700">
          <Settings className="h-4 w-4" />
          Configure
        </button>
      </div>
    ),
  },
};

// With breadcrumbs
export const WithBreadcrumbs: Story = {
  args: {
    title: 'Deployment Details',
    description: 'production-api-v2 running in production environment.',
    breadcrumbs: (
      <nav className="flex items-center gap-2 text-sm text-gray-500 dark:text-gray-400">
        <a href="#" className="hover:text-gray-700 dark:hover:text-gray-300">
          Deployments
        </a>
        <span>/</span>
        <span className="text-gray-900 dark:text-white">production-api-v2</span>
      </nav>
    ),
    action: (
      <button className="px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700">
        Rollback
      </button>
    ),
  },
};

// Real-world: Security Dashboard
export const SecurityDashboard: Story = {
  args: {
    title: 'Security Dashboard',
    description: 'Overview of your organization\'s security posture and compliance status.',
    action: (
      <button className="inline-flex items-center gap-2 px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700">
        <RefreshCw className="h-4 w-4" />
        Refresh Data
      </button>
    ),
  },
};

// Real-world: Vulnerabilities Page
export const VulnerabilitiesPage: Story = {
  args: {
    title: 'Vulnerabilities',
    description: '47 total vulnerabilities detected across 12 deployments.',
    action: (
      <div className="flex gap-2">
        <button className="inline-flex items-center gap-2 px-4 py-2 bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-200 dark:hover:bg-gray-700">
          <Download className="h-4 w-4" />
          Export Report
        </button>
        <button className="inline-flex items-center gap-2 px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700">
          <Settings className="h-4 w-4" />
          Configure Scanning
        </button>
      </div>
    ),
  },
};

// Real-world: Runtime Security
export const RuntimeSecurity: Story = {
  args: {
    title: 'Runtime Security',
    description: 'Monitor drift detection and behavioral anomalies in real-time.',
    breadcrumbs: (
      <nav className="flex items-center gap-2 text-sm text-gray-500 dark:text-gray-400">
        <a href="#" className="hover:text-gray-700 dark:hover:text-gray-300">
          Security
        </a>
        <span>/</span>
        <span className="text-gray-900 dark:text-white">Runtime Security</span>
      </nav>
    ),
    action: (
      <button className="inline-flex items-center gap-2 px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700">
        <Settings className="h-4 w-4" />
        Configure Monitoring
      </button>
    ),
  },
};

// Minimal (title only)
export const Minimal: Story = {
  args: {
    title: 'Simple Page',
  },
};

// Long description
export const LongDescription: Story = {
  args: {
    title: 'Comprehensive Security Analysis',
    description:
      'This page provides a detailed analysis of your security posture, including vulnerability scans, policy compliance checks, deployment security assessments, and runtime threat detection. Use the tools below to investigate specific issues and take corrective action.',
  },
};

// Dark Mode
export const DarkMode: Story = {
  render: () => (
    <div className="dark">
      <div className="bg-gray-950 p-8 rounded-lg">
        <PageHeader
          title="Deployments"
          description="Manage and monitor your application deployments."
          breadcrumbs={
            <nav className="flex items-center gap-2 text-sm text-gray-400">
              <a href="#" className="hover:text-gray-300">
                Home
              </a>
              <span>/</span>
              <span className="text-white">Deployments</span>
            </nav>
          }
          action={
            <button className="inline-flex items-center gap-2 px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700">
              <Plus className="h-4 w-4" />
              New Deployment
            </button>
          }
        />
      </div>
    </div>
  ),
  parameters: {
    backgrounds: { default: 'dark' },
  },
};
