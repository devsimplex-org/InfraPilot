import type { Meta, StoryObj } from '@storybook/react';
import { Timeline } from '@/components/ui/Timeline';
import {
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Package,
  User,
  Shield,
  GitCommit,
  Clock,
  Trash2,
  Settings,
  Upload,
} from 'lucide-react';
import { SeverityBadge, StatusBadge } from '@/components/ui/Badge';

const meta: Meta<typeof Timeline> = {
  title: 'Components/Timeline',
  component: Timeline,
  parameters: {
    layout: 'padded',
  },
  tags: ['autodocs'],
};

export default meta;
type Story = StoryObj<typeof Timeline>;

// Basic Timeline
export const Default: Story = {
  render: () => (
    <Timeline>
      <Timeline.Item
        icon={CheckCircle2}
        iconColor="text-green-600 dark:text-green-400"
        title="Deployment successful"
        timestamp="2 min ago"
      />
      <Timeline.Item
        icon={Package}
        iconColor="text-blue-600 dark:text-blue-400"
        title="Building application"
        timestamp="5 min ago"
      />
      <Timeline.Item
        icon={GitCommit}
        iconColor="text-purple-600 dark:text-purple-400"
        title="Code pushed to repository"
        timestamp="8 min ago"
      />
    </Timeline>
  ),
};

// With descriptions
export const WithDescriptions: Story = {
  render: () => (
    <Timeline>
      <Timeline.Item
        icon={CheckCircle2}
        iconColor="text-green-600 dark:text-green-400"
        title="Deployment completed"
        description="Successfully deployed to production environment"
        timestamp="2 min ago"
      />
      <Timeline.Item
        icon={Package}
        iconColor="text-blue-600 dark:text-blue-400"
        title="Build started"
        description="Building Docker image for production-api-v2"
        timestamp="5 min ago"
      />
      <Timeline.Item
        icon={GitCommit}
        iconColor="text-purple-600 dark:text-purple-400"
        title="Code committed"
        description="feat: Add new authentication endpoint"
        timestamp="8 min ago"
      />
    </Timeline>
  ),
};

// With additional content
export const WithAdditionalContent: Story = {
  render: () => (
    <Timeline>
      <Timeline.Item
        icon={AlertTriangle}
        iconColor="text-red-600 dark:text-red-400"
        title="Critical vulnerability detected"
        timestamp="1 hour ago"
      >
        <div className="bg-red-50 dark:bg-red-900/20 rounded-lg p-3 border border-red-200 dark:border-red-800">
          <div className="flex items-center justify-between mb-2">
            <span className="text-sm font-medium text-gray-900 dark:text-white">
              CVE-2024-12345
            </span>
            <SeverityBadge severity="critical" size="sm" />
          </div>
          <p className="text-xs text-gray-600 dark:text-gray-400">
            OpenSSL remote code execution vulnerability
          </p>
        </div>
      </Timeline.Item>
      <Timeline.Item
        icon={CheckCircle2}
        iconColor="text-green-600 dark:text-green-400"
        title="Security scan completed"
        description="No critical issues found in this scan"
        timestamp="2 hours ago"
      />
    </Timeline>
  ),
};

// Real-world: Deployment History
export const DeploymentHistory: Story = {
  render: () => (
    <div className="w-full max-w-2xl">
      <div className="mb-6">
        <h2 className="text-xl font-semibold text-gray-900 dark:text-white">
          Deployment History
        </h2>
        <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
          production-api-v2 deployment timeline
        </p>
      </div>

      <Timeline>
        <Timeline.Item
          icon={CheckCircle2}
          iconColor="text-green-600 dark:text-green-400"
          title="Deployment successful"
          description="Version v2.4.1 deployed to production"
          timestamp="2 hours ago"
        >
          <div className="text-xs text-gray-600 dark:text-gray-400 space-y-1">
            <div>
              <span className="font-medium">Deployed by:</span> john@example.com
            </div>
            <div>
              <span className="font-medium">Duration:</span> 2m 34s
            </div>
            <div>
              <span className="font-medium">Replicas:</span> 3/3 healthy
            </div>
          </div>
        </Timeline.Item>

        <Timeline.Item
          icon={Package}
          iconColor="text-blue-600 dark:text-blue-400"
          title="Build completed"
          description="Docker image built successfully"
          timestamp="2 hours ago"
        />

        <Timeline.Item
          icon={Shield}
          iconColor="text-purple-600 dark:text-purple-400"
          title="Security scan passed"
          description="0 critical, 2 high, 5 medium vulnerabilities"
          timestamp="2 hours ago"
        />

        <Timeline.Item
          icon={GitCommit}
          iconColor="text-gray-600 dark:text-gray-400"
          title="Commit pushed"
          description="feat: Improve error handling in API endpoints"
          timestamp="3 hours ago"
        />
      </Timeline>
    </div>
  ),
};

// Real-world: Security Audit Log
export const SecurityAuditLog: Story = {
  render: () => (
    <div className="w-full max-w-2xl">
      <div className="mb-6">
        <h2 className="text-xl font-semibold text-gray-900 dark:text-white">
          Security Audit Log
        </h2>
        <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
          Recent security events and policy changes
        </p>
      </div>

      <Timeline>
        <Timeline.Item
          icon={AlertTriangle}
          iconColor="text-red-600 dark:text-red-400"
          title="Critical vulnerability detected"
          timestamp="1 hour ago"
        >
          <div className="bg-red-50 dark:bg-red-900/20 rounded-lg p-3 border border-red-200 dark:border-red-800">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm font-medium text-gray-900 dark:text-white">
                CVE-2024-12345
              </span>
              <SeverityBadge severity="critical" size="sm" />
            </div>
            <p className="text-xs text-gray-600 dark:text-gray-400 mb-2">
              OpenSSL remote code execution vulnerability
            </p>
            <div className="flex gap-2">
              <button className="px-2 py-1 bg-red-600 text-white text-xs rounded hover:bg-red-700">
                Create Fix Task
              </button>
              <button className="px-2 py-1 bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-300 text-xs rounded hover:bg-gray-200 dark:hover:bg-gray-700">
                View Details
              </button>
            </div>
          </div>
        </Timeline.Item>

        <Timeline.Item
          icon={Shield}
          iconColor="text-green-600 dark:text-green-400"
          title="Security policy updated"
          description='Policy "Production Security Requirements" updated by admin@example.com'
          timestamp="3 hours ago"
        />

        <Timeline.Item
          icon={User}
          iconColor="text-blue-600 dark:text-blue-400"
          title="User access granted"
          description="jane@example.com granted Developer role"
          timestamp="5 hours ago"
        />

        <Timeline.Item
          icon={XCircle}
          iconColor="text-orange-600 dark:text-orange-400"
          title="Deployment blocked"
          description="staging-app failed security policy checks"
          timestamp="1 day ago"
        />

        <Timeline.Item
          icon={CheckCircle2}
          iconColor="text-green-600 dark:text-green-400"
          title="Vulnerability resolved"
          description="CVE-2024-11111 fixed in production-api"
          timestamp="2 days ago"
        />
      </Timeline>
    </div>
  ),
};

// Real-world: User Activity
export const UserActivity: Story = {
  render: () => (
    <div className="w-full max-w-2xl">
      <div className="mb-6">
        <h2 className="text-xl font-semibold text-gray-900 dark:text-white">
          Activity Log
        </h2>
        <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
          Recent actions by john@example.com
        </p>
      </div>

      <Timeline>
        <Timeline.Item
          icon={Upload}
          iconColor="text-blue-600 dark:text-blue-400"
          title="Deployed to production"
          description="production-api-v2 v2.4.1"
          timestamp="2 hours ago"
        />

        <Timeline.Item
          icon={Settings}
          iconColor="text-purple-600 dark:text-purple-400"
          title="Updated configuration"
          description="Modified environment variables for staging"
          timestamp="4 hours ago"
        />

        <Timeline.Item
          icon={User}
          iconColor="text-green-600 dark:text-green-400"
          title="Added team member"
          description="Invited alice@example.com as Developer"
          timestamp="1 day ago"
        />

        <Timeline.Item
          icon={Trash2}
          iconColor="text-red-600 dark:text-red-400"
          title="Deleted deployment"
          description="Removed old-staging-app from staging environment"
          timestamp="2 days ago"
        />

        <Timeline.Item
          icon={CheckCircle2}
          iconColor="text-green-600 dark:text-green-400"
          title="Resolved vulnerability"
          description="Updated OpenSSL to v3.0.8"
          timestamp="3 days ago"
        />
      </Timeline>
    </div>
  ),
};

// Without icons
export const WithoutIcons: Story = {
  render: () => (
    <Timeline>
      <Timeline.Item title="Deployment successful" timestamp="2 min ago" />
      <Timeline.Item title="Building application" timestamp="5 min ago" />
      <Timeline.Item title="Code pushed to repository" timestamp="8 min ago" />
    </Timeline>
  ),
};

// Mixed status colors
export const MixedStatusColors: Story = {
  render: () => (
    <Timeline>
      <Timeline.Item
        icon={CheckCircle2}
        iconColor="text-green-600 dark:text-green-400"
        title="Success"
        description="Operation completed successfully"
        timestamp="1 min ago"
      />
      <Timeline.Item
        icon={AlertTriangle}
        iconColor="text-yellow-600 dark:text-yellow-400"
        title="Warning"
        description="High memory usage detected"
        timestamp="5 min ago"
      />
      <Timeline.Item
        icon={XCircle}
        iconColor="text-red-600 dark:text-red-400"
        title="Error"
        description="Connection to database failed"
        timestamp="10 min ago"
      />
      <Timeline.Item
        icon={Clock}
        iconColor="text-gray-600 dark:text-gray-400"
        title="Pending"
        description="Waiting for approval"
        timestamp="15 min ago"
      />
    </Timeline>
  ),
};

// In a card
export const InCard: Story = {
  render: () => (
    <div className="w-96 bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-lg">
      <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
          Recent Activity
        </h3>
      </div>
      <div className="px-6 py-4">
        <Timeline>
          <Timeline.Item
            icon={CheckCircle2}
            iconColor="text-green-600 dark:text-green-400"
            title="Deployment successful"
            timestamp="2 min ago"
          />
          <Timeline.Item
            icon={Package}
            iconColor="text-blue-600 dark:text-blue-400"
            title="Build completed"
            timestamp="5 min ago"
          />
          <Timeline.Item
            icon={GitCommit}
            iconColor="text-purple-600 dark:text-purple-400"
            title="Code committed"
            timestamp="8 min ago"
          />
        </Timeline>
      </div>
    </div>
  ),
};

// Dark Mode
export const DarkMode: Story = {
  render: () => (
    <div className="dark">
      <div className="bg-gray-950 p-8 rounded-lg">
        <div className="mb-6">
          <h2 className="text-xl font-semibold text-white mb-2">
            Deployment History
          </h2>
          <p className="text-sm text-gray-400">Recent deployment events</p>
        </div>

        <Timeline>
          <Timeline.Item
            icon={CheckCircle2}
            iconColor="text-green-600 dark:text-green-400"
            title="Deployment successful"
            description="Version v2.4.1 deployed to production"
            timestamp="2 hours ago"
          />
          <Timeline.Item
            icon={Package}
            iconColor="text-blue-600 dark:text-blue-400"
            title="Build completed"
            description="Docker image built successfully"
            timestamp="2 hours ago"
          />
          <Timeline.Item
            icon={Shield}
            iconColor="text-purple-600 dark:text-purple-400"
            title="Security scan passed"
            description="0 critical vulnerabilities found"
            timestamp="2 hours ago"
          />
          <Timeline.Item
            icon={GitCommit}
            iconColor="text-gray-400"
            title="Commit pushed"
            description="feat: Improve error handling"
            timestamp="3 hours ago"
          />
        </Timeline>
      </div>
    </div>
  ),
  parameters: {
    backgrounds: { default: 'dark' },
  },
};
