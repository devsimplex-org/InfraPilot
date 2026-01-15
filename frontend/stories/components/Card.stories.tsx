import type { Meta, StoryObj } from '@storybook/react';
import { Card } from '@/components/ui/Card';
import { SeverityBadge } from '@/components/ui/Badge';
import { AlertTriangle, RefreshCw } from 'lucide-react';

const meta: Meta<typeof Card> = {
  title: 'Components/Card',
  component: Card,
  parameters: {
    layout: 'centered',
  },
  tags: ['autodocs'],
};

export default meta;
type Story = StoryObj<typeof Card>;

// Basic Cards
export const Default: Story = {
  render: () => (
    <Card className="w-96">
      <Card.Body>
        <p className="text-gray-700 dark:text-gray-300">
          This is a default card with simple content.
        </p>
      </Card.Body>
    </Card>
  ),
};

export const WithHeader: Story = {
  render: () => (
    <Card className="w-96">
      <Card.Header>
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
          Card Title
        </h3>
      </Card.Header>
      <Card.Body>
        <p className="text-gray-700 dark:text-gray-300">
          This card has a header section with a title.
        </p>
      </Card.Body>
    </Card>
  ),
};

export const WithHeaderAndAction: Story = {
  render: () => (
    <Card className="w-96">
      <Card.Header
        action={
          <button className="text-sm text-primary-600 hover:text-primary-700 dark:text-primary-400 flex items-center gap-1">
            <RefreshCw className="h-4 w-4" />
            Refresh
          </button>
        }
      >
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
          Vulnerabilities
        </h3>
      </Card.Header>
      <Card.Body>
        <p className="text-gray-700 dark:text-gray-300">
          12 critical vulnerabilities detected in your deployments.
        </p>
      </Card.Body>
    </Card>
  ),
};

export const WithFooter: Story = {
  render: () => (
    <Card className="w-96">
      <Card.Header>
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
          Deployment Summary
        </h3>
      </Card.Header>
      <Card.Body>
        <p className="text-gray-700 dark:text-gray-300">
          Last deployment was successful with no issues detected.
        </p>
      </Card.Body>
      <Card.Footer>
        <button className="px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 text-sm">
          View Details
        </button>
      </Card.Footer>
    </Card>
  ),
};

export const CompactMode: Story = {
  render: () => (
    <Card className="w-96">
      <Card.Header>
        <h3 className="text-base font-semibold text-gray-900 dark:text-white">
          Compact Card
        </h3>
      </Card.Header>
      <Card.Body compact>
        <p className="text-sm text-gray-700 dark:text-gray-300">
          This card uses compact mode for reduced padding.
        </p>
      </Card.Body>
    </Card>
  ),
};

// Variants
export const AllVariants: Story = {
  render: () => (
    <div className="flex flex-col gap-6">
      <div className="space-y-2">
        <h3 className="text-sm font-semibold text-gray-700 dark:text-gray-300">Default</h3>
        <Card className="w-96">
          <Card.Body>
            <p className="text-gray-700 dark:text-gray-300">
              Default card with border and no shadow.
            </p>
          </Card.Body>
        </Card>
      </div>

      <div className="space-y-2">
        <h3 className="text-sm font-semibold text-gray-700 dark:text-gray-300">Elevated</h3>
        <Card variant="elevated" className="w-96">
          <Card.Body>
            <p className="text-gray-700 dark:text-gray-300">
              Elevated card with shadow, no border.
            </p>
          </Card.Body>
        </Card>
      </div>

      <div className="space-y-2">
        <h3 className="text-sm font-semibold text-gray-700 dark:text-gray-300">Bordered</h3>
        <Card variant="bordered" className="w-96">
          <Card.Body>
            <p className="text-gray-700 dark:text-gray-300">
              Bordered card with thick 2px border.
            </p>
          </Card.Body>
        </Card>
      </div>
    </div>
  ),
};

// Interactive
export const Interactive: Story = {
  render: () => (
    <Card className="w-96" interactive>
      <Card.Body>
        <p className="text-gray-700 dark:text-gray-300">
          Hover over this card to see the interactive effect.
        </p>
      </Card.Body>
    </Card>
  ),
};

export const Clickable: Story = {
  render: () => (
    <Card className="w-96" onClick={() => alert('Card clicked!')}>
      <Card.Body>
        <p className="text-gray-700 dark:text-gray-300">
          Click this card to trigger an action.
        </p>
      </Card.Body>
    </Card>
  ),
};

// Real-world Examples
export const VulnerabilityCard: Story = {
  render: () => (
    <Card className="w-96">
      <Card.Header
        action={
          <button className="text-sm text-primary-600 hover:text-primary-700 dark:text-primary-400">
            View All
          </button>
        }
      >
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
          Critical Vulnerabilities
        </h3>
      </Card.Header>
      <Card.Body>
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-900 dark:text-white">CVE-2024-12345</p>
              <p className="text-xs text-gray-500 dark:text-gray-400">OpenSSL vulnerability</p>
            </div>
            <SeverityBadge severity="critical" size="sm" />
          </div>
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-900 dark:text-white">CVE-2024-12346</p>
              <p className="text-xs text-gray-500 dark:text-gray-400">Redis vulnerability</p>
            </div>
            <SeverityBadge severity="high" size="sm" />
          </div>
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-900 dark:text-white">CVE-2024-12347</p>
              <p className="text-xs text-gray-500 dark:text-gray-400">Node.js vulnerability</p>
            </div>
            <SeverityBadge severity="high" size="sm" />
          </div>
        </div>
      </Card.Body>
      <Card.Footer>
        <button className="w-full px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 text-sm font-medium">
          Create Fix Task
        </button>
      </Card.Footer>
    </Card>
  ),
};

export const DeploymentCard: Story = {
  render: () => (
    <Card className="w-96">
      <Card.Header>
        <div>
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
            production-api-v2
          </h3>
          <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
            Deployed 2 hours ago
          </p>
        </div>
      </Card.Header>
      <Card.Body>
        <div className="space-y-2">
          <div className="flex justify-between text-sm">
            <span className="text-gray-500 dark:text-gray-400">Status</span>
            <span className="text-green-600 dark:text-green-400 font-medium">Healthy</span>
          </div>
          <div className="flex justify-between text-sm">
            <span className="text-gray-500 dark:text-gray-400">Vulnerabilities</span>
            <span className="text-gray-900 dark:text-white font-medium">0 Critical</span>
          </div>
          <div className="flex justify-between text-sm">
            <span className="text-gray-500 dark:text-gray-400">Policy Compliance</span>
            <span className="text-green-600 dark:text-green-400 font-medium">Passed</span>
          </div>
        </div>
      </Card.Body>
      <Card.Footer>
        <div className="flex gap-2">
          <button className="flex-1 px-4 py-2 bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-200 dark:hover:bg-gray-700 text-sm">
            View Logs
          </button>
          <button className="flex-1 px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 text-sm">
            Rollback
          </button>
        </div>
      </Card.Footer>
    </Card>
  ),
};

// Dark Mode
export const DarkMode: Story = {
  render: () => (
    <div className="dark">
      <div className="bg-gray-950 p-8 rounded-lg space-y-6">
        <Card className="w-96">
          <Card.Header>
            <h3 className="text-lg font-semibold text-white">Dark Mode Card</h3>
          </Card.Header>
          <Card.Body>
            <p className="text-gray-300">
              This card demonstrates dark mode styling.
            </p>
          </Card.Body>
        </Card>

        <Card variant="elevated" className="w-96">
          <Card.Header
            action={
              <button className="text-sm text-primary-400 hover:text-primary-300">
                Action
              </button>
            }
          >
            <h3 className="text-lg font-semibold text-white">Elevated Card</h3>
          </Card.Header>
          <Card.Body>
            <p className="text-gray-300">
              Elevated variant in dark mode with shadow.
            </p>
          </Card.Body>
          <Card.Footer>
            <button className="w-full px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 text-sm">
              Primary Action
            </button>
          </Card.Footer>
        </Card>
      </div>
    </div>
  ),
  parameters: {
    backgrounds: { default: 'dark' },
  },
};
