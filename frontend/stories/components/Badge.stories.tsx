import type { Meta, StoryObj } from '@storybook/react';
import { Badge, SeverityBadge, StatusBadge } from '@/components/ui/Badge';
import { AlertTriangle, CheckCircle2, ShieldAlert, XCircle } from 'lucide-react';

const meta: Meta<typeof Badge> = {
  title: 'Components/Badge',
  component: Badge,
  parameters: {
    layout: 'centered',
  },
  tags: ['autodocs'],
  argTypes: {
    variant: {
      control: 'select',
      options: ['default', 'severity', 'status'],
    },
    size: {
      control: 'select',
      options: ['sm', 'md', 'lg'],
    },
  },
};

export default meta;
type Story = StoryObj<typeof Badge>;

// Default Badge
export const Default: Story = {
  args: {
    children: 'Default Badge',
  },
};

export const WithIcon: Story = {
  args: {
    children: 'Badge with Icon',
    icon: AlertTriangle,
  },
};

// Severity Badges
export const AllSeverities: Story = {
  render: () => (
    <div className="flex flex-col gap-4">
      <div className="space-y-2">
        <h3 className="text-sm font-semibold text-gray-700 dark:text-gray-300">Small Size</h3>
        <div className="flex flex-wrap gap-2">
          <SeverityBadge severity="critical" size="sm" />
          <SeverityBadge severity="high" size="sm" />
          <SeverityBadge severity="medium" size="sm" />
          <SeverityBadge severity="low" size="sm" />
          <SeverityBadge severity="info" size="sm" />
        </div>
      </div>

      <div className="space-y-2">
        <h3 className="text-sm font-semibold text-gray-700 dark:text-gray-300">Medium Size (Default)</h3>
        <div className="flex flex-wrap gap-2">
          <SeverityBadge severity="critical" />
          <SeverityBadge severity="high" />
          <SeverityBadge severity="medium" />
          <SeverityBadge severity="low" />
          <SeverityBadge severity="info" />
        </div>
      </div>

      <div className="space-y-2">
        <h3 className="text-sm font-semibold text-gray-700 dark:text-gray-300">Large Size</h3>
        <div className="flex flex-wrap gap-2">
          <SeverityBadge severity="critical" size="lg" />
          <SeverityBadge severity="high" size="lg" />
          <SeverityBadge severity="medium" size="lg" />
          <SeverityBadge severity="low" size="lg" />
          <SeverityBadge severity="info" size="lg" />
        </div>
      </div>
    </div>
  ),
};

export const SeverityWithIcons: Story = {
  render: () => (
    <div className="flex flex-wrap gap-2">
      <SeverityBadge severity="critical" icon={XCircle} />
      <SeverityBadge severity="high" icon={AlertTriangle} />
      <SeverityBadge severity="medium" icon={ShieldAlert} />
      <SeverityBadge severity="low" icon={AlertTriangle} />
      <SeverityBadge severity="info" icon={CheckCircle2} />
    </div>
  ),
};

// Status Badges
export const AllStatuses: Story = {
  render: () => (
    <div className="flex flex-col gap-4">
      <div className="space-y-2">
        <h3 className="text-sm font-semibold text-gray-700 dark:text-gray-300">Small Size</h3>
        <div className="flex flex-wrap gap-2">
          <StatusBadge status="healthy" size="sm" />
          <StatusBadge status="warning" size="sm" />
          <StatusBadge status="degraded" size="sm" />
          <StatusBadge status="critical" size="sm" />
        </div>
      </div>

      <div className="space-y-2">
        <h3 className="text-sm font-semibold text-gray-700 dark:text-gray-300">Medium Size (Default)</h3>
        <div className="flex flex-wrap gap-2">
          <StatusBadge status="healthy" />
          <StatusBadge status="warning" />
          <StatusBadge status="degraded" />
          <StatusBadge status="critical" />
        </div>
      </div>

      <div className="space-y-2">
        <h3 className="text-sm font-semibold text-gray-700 dark:text-gray-300">Large Size</h3>
        <div className="flex flex-wrap gap-2">
          <StatusBadge status="healthy" size="lg" />
          <StatusBadge status="warning" size="lg" />
          <StatusBadge status="degraded" size="lg" />
          <StatusBadge status="critical" size="lg" />
        </div>
      </div>
    </div>
  ),
};

export const StatusWithIcons: Story = {
  render: () => (
    <div className="flex flex-wrap gap-2">
      <StatusBadge status="healthy" icon={CheckCircle2} />
      <StatusBadge status="warning" icon={AlertTriangle} />
      <StatusBadge status="degraded" icon={ShieldAlert} />
      <StatusBadge status="critical" icon={XCircle} />
    </div>
  ),
};

// Real-world usage examples
export const InTable: Story = {
  render: () => (
    <div className="w-full max-w-4xl">
      <table className="w-full border-collapse">
        <thead className="bg-gray-50 dark:bg-gray-900">
          <tr>
            <th className="px-4 py-3 text-left text-sm font-medium text-gray-700 dark:text-gray-300 border-b border-gray-200 dark:border-gray-800">
              CVE ID
            </th>
            <th className="px-4 py-3 text-left text-sm font-medium text-gray-700 dark:text-gray-300 border-b border-gray-200 dark:border-gray-800">
              Severity
            </th>
            <th className="px-4 py-3 text-left text-sm font-medium text-gray-700 dark:text-gray-300 border-b border-gray-200 dark:border-gray-800">
              Status
            </th>
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-200 dark:divide-gray-800">
          <tr>
            <td className="px-4 py-3 text-sm text-gray-900 dark:text-white">CVE-2024-12345</td>
            <td className="px-4 py-3">
              <SeverityBadge severity="critical" size="sm" />
            </td>
            <td className="px-4 py-3">
              <StatusBadge status="critical" size="sm" icon={XCircle}>
                Unresolved
              </StatusBadge>
            </td>
          </tr>
          <tr>
            <td className="px-4 py-3 text-sm text-gray-900 dark:text-white">CVE-2024-12346</td>
            <td className="px-4 py-3">
              <SeverityBadge severity="high" size="sm" />
            </td>
            <td className="px-4 py-3">
              <StatusBadge status="warning" size="sm" icon={AlertTriangle}>
                In Progress
              </StatusBadge>
            </td>
          </tr>
          <tr>
            <td className="px-4 py-3 text-sm text-gray-900 dark:text-white">CVE-2024-12347</td>
            <td className="px-4 py-3">
              <SeverityBadge severity="medium" size="sm" />
            </td>
            <td className="px-4 py-3">
              <StatusBadge status="healthy" size="sm" icon={CheckCircle2}>
                Resolved
              </StatusBadge>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  ),
};

export const DarkMode: Story = {
  render: () => (
    <div className="dark">
      <div className="bg-gray-950 p-8 rounded-lg">
        <div className="space-y-4">
          <div className="space-y-2">
            <h3 className="text-sm font-semibold text-white">Severity Badges (Dark Mode)</h3>
            <div className="flex flex-wrap gap-2">
              <SeverityBadge severity="critical" />
              <SeverityBadge severity="high" />
              <SeverityBadge severity="medium" />
              <SeverityBadge severity="low" />
              <SeverityBadge severity="info" />
            </div>
          </div>

          <div className="space-y-2">
            <h3 className="text-sm font-semibold text-white">Status Badges (Dark Mode)</h3>
            <div className="flex flex-wrap gap-2">
              <StatusBadge status="healthy" />
              <StatusBadge status="warning" />
              <StatusBadge status="degraded" />
              <StatusBadge status="critical" />
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
