import type { Meta, StoryObj } from '@storybook/react';
import { EmptyState } from '@/components/ui/EmptyState';
import {
  Inbox,
  AlertTriangle,
  Search,
  Package,
  ShieldAlert,
  Users,
  FileText,
  Database,
  CheckCircle2,
} from 'lucide-react';

const meta: Meta<typeof EmptyState> = {
  title: 'Components/EmptyState',
  component: EmptyState,
  parameters: {
    layout: 'centered',
  },
  tags: ['autodocs'],
};

export default meta;
type Story = StoryObj<typeof EmptyState>;

// Basic EmptyState
export const Default: Story = {
  args: {
    icon: Inbox,
    title: 'No items found',
    description: 'Get started by creating your first item.',
  },
};

// With action button
export const WithAction: Story = {
  args: {
    icon: Package,
    title: 'No deployments yet',
    description: 'Deploy your first application to get started with InfraPilot.',
    action: (
      <button className="px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700">
        Create Deployment
      </button>
    ),
  },
};

// Different sizes
export const Sizes: Story = {
  render: () => (
    <div className="space-y-12">
      <div className="border border-gray-200 dark:border-gray-700 rounded-lg p-4">
        <h3 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-4">
          Small
        </h3>
        <EmptyState
          icon={Inbox}
          title="No items"
          description="No items to display"
          size="sm"
        />
      </div>

      <div className="border border-gray-200 dark:border-gray-700 rounded-lg p-4">
        <h3 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-4">
          Medium (Default)
        </h3>
        <EmptyState
          icon={Inbox}
          title="No items found"
          description="Get started by creating your first item."
          size="md"
        />
      </div>

      <div className="border border-gray-200 dark:border-gray-700 rounded-lg p-4">
        <h3 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-4">
          Large
        </h3>
        <EmptyState
          icon={Inbox}
          title="No items found"
          description="Get started by creating your first item and unlock the full potential of your application."
          size="lg"
        />
      </div>
    </div>
  ),
};

// No search results
export const NoSearchResults: Story = {
  args: {
    icon: Search,
    title: 'No results found',
    description: 'Try adjusting your search or filters to find what you\'re looking for.',
  },
};

// Error state
export const ErrorState: Story = {
  args: {
    icon: AlertTriangle,
    title: 'Unable to load data',
    description: 'There was an error loading the data. Please try again.',
    iconClassName: 'text-red-500 dark:text-red-400',
    action: (
      <button className="px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700">
        Retry
      </button>
    ),
  },
};

// Real-world: No Vulnerabilities
export const NoVulnerabilities: Story = {
  args: {
    icon: CheckCircle2,
    title: 'No vulnerabilities detected',
    description: 'All your deployments are secure with no known vulnerabilities.',
    iconClassName: 'text-green-500 dark:text-green-400',
  },
};

// Real-world: No Deployments
export const NoDeployments: Story = {
  args: {
    icon: Package,
    title: 'No deployments yet',
    description: 'Deploy your first application to start monitoring security and compliance.',
    action: (
      <div className="flex gap-2">
        <button className="px-4 py-2 bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-200 dark:hover:bg-gray-700">
          View Documentation
        </button>
        <button className="px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700">
          Create Deployment
        </button>
      </div>
    ),
  },
};

// Real-world: No Users
export const NoUsers: Story = {
  args: {
    icon: Users,
    title: 'No users in this organization',
    description: 'Invite team members to collaborate on your security posture.',
    action: (
      <button className="px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700">
        Invite Users
      </button>
    ),
  },
};

// Real-world: No Policies
export const NoPolicies: Story = {
  args: {
    icon: ShieldAlert,
    title: 'No security policies configured',
    description: 'Create your first policy to enforce security requirements across deployments.',
    action: (
      <button className="px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700">
        Create Policy
      </button>
    ),
  },
};

// Real-world: No Logs
export const NoLogs: Story = {
  args: {
    icon: FileText,
    title: 'No logs available',
    description: 'Logs will appear here once your application starts generating events.',
  },
};

// Real-world: No Data Sources
export const NoDataSources: Story = {
  args: {
    icon: Database,
    title: 'No data sources connected',
    description: 'Connect your first data source to start analyzing security posture.',
    action: (
      <button className="px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700">
        Add Data Source
      </button>
    ),
  },
};

// Minimal (no icon, no description)
export const Minimal: Story = {
  args: {
    title: 'No items',
  },
};

// With custom icon color
export const CustomIconColor: Story = {
  args: {
    icon: AlertTriangle,
    title: 'Action required',
    description: 'Some deployments require immediate attention.',
    iconClassName: 'text-orange-500 dark:text-orange-400',
    action: (
      <button className="px-4 py-2 bg-orange-600 text-white rounded-lg hover:bg-orange-700">
        View Deployments
      </button>
    ),
  },
};

// In a card
export const InCard: Story = {
  render: () => (
    <div className="w-96 bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-lg">
      <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
          Recent Deployments
        </h3>
      </div>
      <div className="px-6 pb-6">
        <EmptyState
          icon={Package}
          title="No recent deployments"
          description="Deployments will appear here once you start deploying applications."
          size="sm"
        />
      </div>
    </div>
  ),
};

// In a table
export const InTable: Story = {
  render: () => (
    <div className="w-full max-w-4xl border border-gray-200 dark:border-gray-700 rounded-lg overflow-hidden">
      <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
        <thead className="bg-gray-50 dark:bg-gray-800">
          <tr>
            <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300 uppercase">
              Name
            </th>
            <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300 uppercase">
              Status
            </th>
            <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300 uppercase">
              Severity
            </th>
          </tr>
        </thead>
        <tbody className="bg-white dark:bg-gray-900">
          <tr>
            <td colSpan={3}>
              <EmptyState
                icon={ShieldAlert}
                title="No vulnerabilities found"
                description="All deployments are secure."
                size="sm"
              />
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  ),
};

// Dark Mode
export const DarkMode: Story = {
  render: () => (
    <div className="dark">
      <div className="bg-gray-950 p-8 rounded-lg">
        <EmptyState
          icon={Package}
          title="No deployments yet"
          description="Deploy your first application to start monitoring security and compliance."
          action={
            <button className="px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700">
              Create Deployment
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
