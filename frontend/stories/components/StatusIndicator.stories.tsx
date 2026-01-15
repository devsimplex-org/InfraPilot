import type { Meta, StoryObj } from '@storybook/react';
import { StatusIndicator } from '@/components/ui/StatusIndicator';

const meta: Meta<typeof StatusIndicator> = {
  title: 'Components/StatusIndicator',
  component: StatusIndicator,
  parameters: {
    layout: 'centered',
  },
  tags: ['autodocs'],
};

export default meta;
type Story = StoryObj<typeof StatusIndicator>;

// Basic statuses
export const Healthy: Story = {
  args: {
    status: 'healthy',
  },
};

export const Warning: Story = {
  args: {
    status: 'warning',
  },
};

export const Degraded: Story = {
  args: {
    status: 'degraded',
  },
};

export const Critical: Story = {
  args: {
    status: 'critical',
  },
};

// With pulse animation
export const HealthyWithPulse: Story = {
  args: {
    status: 'healthy',
    pulse: true,
  },
};

export const CriticalWithPulse: Story = {
  args: {
    status: 'critical',
    pulse: true,
  },
};

// Different sizes
export const Sizes: Story = {
  render: () => (
    <div className="flex flex-col gap-6">
      <div className="space-y-2">
        <h3 className="text-sm font-semibold text-gray-700 dark:text-gray-300">Small</h3>
        <div className="flex gap-4">
          <StatusIndicator status="healthy" size="sm" />
          <StatusIndicator status="warning" size="sm" />
          <StatusIndicator status="degraded" size="sm" />
          <StatusIndicator status="critical" size="sm" />
        </div>
      </div>

      <div className="space-y-2">
        <h3 className="text-sm font-semibold text-gray-700 dark:text-gray-300">Medium (Default)</h3>
        <div className="flex gap-4">
          <StatusIndicator status="healthy" size="md" />
          <StatusIndicator status="warning" size="md" />
          <StatusIndicator status="degraded" size="md" />
          <StatusIndicator status="critical" size="md" />
        </div>
      </div>

      <div className="space-y-2">
        <h3 className="text-sm font-semibold text-gray-700 dark:text-gray-300">Large</h3>
        <div className="flex gap-4">
          <StatusIndicator status="healthy" size="lg" />
          <StatusIndicator status="warning" size="lg" />
          <StatusIndicator status="degraded" size="lg" />
          <StatusIndicator status="critical" size="lg" />
        </div>
      </div>
    </div>
  ),
};

// All statuses
export const AllStatuses: Story = {
  render: () => (
    <div className="flex flex-col gap-3">
      <StatusIndicator status="healthy" />
      <StatusIndicator status="warning" />
      <StatusIndicator status="degraded" />
      <StatusIndicator status="critical" />
    </div>
  ),
};

// All statuses with pulse
export const AllStatusesWithPulse: Story = {
  render: () => (
    <div className="flex flex-col gap-3">
      <StatusIndicator status="healthy" pulse />
      <StatusIndicator status="warning" pulse />
      <StatusIndicator status="degraded" pulse />
      <StatusIndicator status="critical" pulse />
    </div>
  ),
};

// Without labels
export const WithoutLabels: Story = {
  render: () => (
    <div className="flex gap-4">
      <StatusIndicator status="healthy" showLabel={false} />
      <StatusIndicator status="warning" showLabel={false} />
      <StatusIndicator status="degraded" showLabel={false} />
      <StatusIndicator status="critical" showLabel={false} />
    </div>
  ),
};

// Without labels with pulse
export const WithoutLabelsWithPulse: Story = {
  render: () => (
    <div className="flex gap-4">
      <StatusIndicator status="healthy" showLabel={false} pulse />
      <StatusIndicator status="warning" showLabel={false} pulse />
      <StatusIndicator status="degraded" showLabel={false} pulse />
      <StatusIndicator status="critical" showLabel={false} pulse />
    </div>
  ),
};

// Custom labels
export const CustomLabels: Story = {
  render: () => (
    <div className="flex flex-col gap-3">
      <StatusIndicator status="healthy" label="Online" pulse />
      <StatusIndicator status="warning" label="High Load" />
      <StatusIndicator status="degraded" label="Recovering" />
      <StatusIndicator status="critical" label="Offline" pulse />
    </div>
  ),
};

// In a list
export const InList: Story = {
  render: () => (
    <div className="w-96 bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-lg divide-y divide-gray-200 dark:divide-gray-700">
      <div className="px-4 py-3 flex items-center justify-between">
        <span className="text-sm text-gray-700 dark:text-gray-300">Database Server</span>
        <StatusIndicator status="healthy" pulse size="sm" />
      </div>
      <div className="px-4 py-3 flex items-center justify-between">
        <span className="text-sm text-gray-700 dark:text-gray-300">API Gateway</span>
        <StatusIndicator status="warning" size="sm" />
      </div>
      <div className="px-4 py-3 flex items-center justify-between">
        <span className="text-sm text-gray-700 dark:text-gray-300">Cache Server</span>
        <StatusIndicator status="degraded" size="sm" />
      </div>
      <div className="px-4 py-3 flex items-center justify-between">
        <span className="text-sm text-gray-700 dark:text-gray-300">Worker Nodes</span>
        <StatusIndicator status="critical" pulse size="sm" />
      </div>
    </div>
  ),
};

// Real-world: Service Status Dashboard
export const ServiceStatusDashboard: Story = {
  render: () => (
    <div className="w-full max-w-4xl space-y-6">
      <div>
        <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-2">
          System Status
        </h2>
        <p className="text-sm text-gray-500 dark:text-gray-400">
          Real-time status of all services
        </p>
      </div>

      <div className="grid grid-cols-2 gap-4">
        {/* Production Services */}
        <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-lg p-4">
          <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-4 uppercase tracking-wide">
            Production
          </h3>
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-700 dark:text-gray-300">API Server</span>
              <StatusIndicator status="healthy" pulse size="sm" />
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-700 dark:text-gray-300">Database</span>
              <StatusIndicator status="healthy" pulse size="sm" />
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-700 dark:text-gray-300">Redis Cache</span>
              <StatusIndicator status="healthy" pulse size="sm" />
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-700 dark:text-gray-300">Message Queue</span>
              <StatusIndicator status="warning" size="sm" />
            </div>
          </div>
        </div>

        {/* Staging Services */}
        <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-lg p-4">
          <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-4 uppercase tracking-wide">
            Staging
          </h3>
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-700 dark:text-gray-300">API Server</span>
              <StatusIndicator status="healthy" size="sm" />
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-700 dark:text-gray-300">Database</span>
              <StatusIndicator status="degraded" size="sm" />
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-700 dark:text-gray-300">Redis Cache</span>
              <StatusIndicator status="healthy" size="sm" />
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-gray-700 dark:text-gray-300">Message Queue</span>
              <StatusIndicator status="critical" pulse size="sm" />
            </div>
          </div>
        </div>
      </div>
    </div>
  ),
};

// Real-world: Deployment Status
export const DeploymentStatus: Story = {
  render: () => (
    <div className="w-96 bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-lg">
      <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
          Active Deployments
        </h3>
      </div>
      <div className="divide-y divide-gray-200 dark:divide-gray-700">
        <div className="px-6 py-4">
          <div className="flex items-start justify-between mb-2">
            <div>
              <p className="text-sm font-medium text-gray-900 dark:text-white">
                production-api-v2
              </p>
              <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                Deployed 2 hours ago
              </p>
            </div>
            <StatusIndicator status="healthy" pulse size="sm" />
          </div>
        </div>
        <div className="px-6 py-4">
          <div className="flex items-start justify-between mb-2">
            <div>
              <p className="text-sm font-medium text-gray-900 dark:text-white">
                staging-web-app
              </p>
              <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                Deployed 4 hours ago
              </p>
            </div>
            <StatusIndicator status="warning" size="sm" />
          </div>
        </div>
        <div className="px-6 py-4">
          <div className="flex items-start justify-between mb-2">
            <div>
              <p className="text-sm font-medium text-gray-900 dark:text-white">
                dev-api-gateway
              </p>
              <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                Deployed 1 day ago
              </p>
            </div>
            <StatusIndicator status="critical" pulse size="sm" />
          </div>
        </div>
      </div>
    </div>
  ),
};

// In table
export const InTable: Story = {
  render: () => (
    <div className="w-full max-w-4xl border border-gray-200 dark:border-gray-700 rounded-lg overflow-hidden">
      <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
        <thead className="bg-gray-50 dark:bg-gray-800">
          <tr>
            <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300 uppercase">
              Deployment
            </th>
            <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300 uppercase">
              Environment
            </th>
            <th className="px-6 py-3 text-center text-xs font-semibold text-gray-700 dark:text-gray-300 uppercase">
              Status
            </th>
          </tr>
        </thead>
        <tbody className="bg-white dark:bg-gray-900 divide-y divide-gray-200 dark:divide-gray-700">
          <tr>
            <td className="px-6 py-4 text-sm text-gray-900 dark:text-white">production-api</td>
            <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">production</td>
            <td className="px-6 py-4 text-center">
              <div className="flex justify-center">
                <StatusIndicator status="healthy" pulse size="sm" />
              </div>
            </td>
          </tr>
          <tr>
            <td className="px-6 py-4 text-sm text-gray-900 dark:text-white">staging-web</td>
            <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">staging</td>
            <td className="px-6 py-4 text-center">
              <div className="flex justify-center">
                <StatusIndicator status="warning" size="sm" />
              </div>
            </td>
          </tr>
          <tr>
            <td className="px-6 py-4 text-sm text-gray-900 dark:text-white">dev-gateway</td>
            <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">development</td>
            <td className="px-6 py-4 text-center">
              <div className="flex justify-center">
                <StatusIndicator status="critical" pulse size="sm" />
              </div>
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
      <div className="bg-gray-950 p-8 rounded-lg space-y-6">
        <div>
          <h2 className="text-xl font-semibold text-white mb-4">System Status</h2>
          <div className="space-y-3">
            <StatusIndicator status="healthy" pulse />
            <StatusIndicator status="warning" />
            <StatusIndicator status="degraded" />
            <StatusIndicator status="critical" pulse />
          </div>
        </div>

        <div className="grid grid-cols-2 gap-4">
          <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
            <h3 className="text-sm font-semibold text-white mb-3 uppercase tracking-wide">
              Services
            </h3>
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-300">API</span>
                <StatusIndicator status="healthy" pulse size="sm" />
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-300">Database</span>
                <StatusIndicator status="warning" size="sm" />
              </div>
            </div>
          </div>
          <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
            <h3 className="text-sm font-semibold text-white mb-3 uppercase tracking-wide">
              Workers
            </h3>
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-300">Queue</span>
                <StatusIndicator status="healthy" size="sm" />
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-300">Scheduler</span>
                <StatusIndicator status="critical" pulse size="sm" />
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  ),
  parameters: {
    backgrounds: { default: 'dark' },
  },
};
