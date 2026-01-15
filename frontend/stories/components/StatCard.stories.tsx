import type { Meta, StoryObj } from '@storybook/react';
import { StatCard, MetricsGrid } from '@/components/ui/StatCard';
import { AlertTriangle, CheckCircle2, XCircle, ShieldAlert, Package, TrendingUp } from 'lucide-react';

const meta: Meta<typeof StatCard> = {
  title: 'Components/StatCard',
  component: StatCard,
  parameters: {
    layout: 'centered',
  },
  tags: ['autodocs'],
};

export default meta;
type Story = StoryObj<typeof StatCard>;

// Basic StatCards
export const Default: Story = {
  args: {
    label: 'Total Deployments',
    value: 42,
  },
};

export const WithIcon: Story = {
  args: {
    label: 'Critical Vulnerabilities',
    value: 12,
    icon: AlertTriangle,
    iconColor: 'text-red-600',
    valueColor: 'text-red-600 dark:text-red-400',
  },
};

export const WithTrend: Story = {
  args: {
    label: 'Deployments (7d)',
    value: 28,
    icon: Package,
    trend: 'up',
    trendValue: '+12% from last week',
  },
};

export const WithDescription: Story = {
  args: {
    label: 'Policy Compliance',
    value: '98%',
    description: 'All deployments passed security policies',
    icon: CheckCircle2,
    iconColor: 'text-green-600',
    valueColor: 'text-green-600 dark:text-green-400',
  },
};

// Trend Variations
export const AllTrends: Story = {
  render: () => (
    <div className="flex flex-col gap-4">
      <div className="space-y-2">
        <h3 className="text-sm font-semibold text-gray-700 dark:text-gray-300">Trend Up (Positive)</h3>
        <StatCard
          label="Successful Deployments"
          value={145}
          icon={CheckCircle2}
          trend="up"
          trendValue="+23% from last week"
          iconColor="text-green-600"
        />
      </div>

      <div className="space-y-2">
        <h3 className="text-sm font-semibold text-gray-700 dark:text-gray-300">Trend Down (Negative)</h3>
        <StatCard
          label="Critical Vulnerabilities"
          value={8}
          icon={XCircle}
          trend="down"
          trendValue="-40% from last week"
          iconColor="text-red-600"
          valueColor="text-red-600 dark:text-red-400"
        />
      </div>

      <div className="space-y-2">
        <h3 className="text-sm font-semibold text-gray-700 dark:text-gray-300">No Trend (Neutral)</h3>
        <StatCard
          label="Active Containers"
          value={32}
          icon="Package"
          iconColor="text-blue-600"
        />
      </div>
    </div>
  ),
};

// Real-world Security Metrics
export const SecurityMetrics: Story = {
  render: () => (
    <MetricsGrid columns={4}>
      <StatCard
        label="Critical Vulnerabilities"
        value={12}
        icon={XCircle}
        trend="down"
        trendValue="-3 from yesterday"
        iconColor="text-red-600"
        valueColor="text-red-600 dark:text-red-400"
      />
      <StatCard
        label="High Severity"
        value={45}
        icon={AlertTriangle}
        trend="up"
        trendValue="+5 from yesterday"
        iconColor="text-orange-600"
        valueColor="text-orange-600 dark:text-orange-400"
      />
      <StatCard
        label="Medium Severity"
        value={128}
        icon={ShieldAlert}
        iconColor="text-yellow-600"
        valueColor="text-yellow-600 dark:text-yellow-400"
      />
      <StatCard
        label="Resolved (7d)"
        value={67}
        icon={CheckCircle2}
        trend="up"
        trendValue="+12 from last week"
        iconColor="text-green-600"
        valueColor="text-green-600 dark:text-green-400"
      />
    </MetricsGrid>
  ),
};

// Deployment Metrics
export const DeploymentMetrics: Story = {
  render: () => (
    <MetricsGrid columns={4}>
      <StatCard
        label="Total Deployments"
        value={156}
        icon={Package}
        description="Last 30 days"
        iconColor="text-blue-600"
      />
      <StatCard
        label="Successful"
        value={148}
        icon={CheckCircle2}
        trend="up"
        trendValue="95% success rate"
        iconColor="text-green-600"
        valueColor="text-green-600 dark:text-green-400"
      />
      <StatCard
        label="Failed"
        value={5}
        icon={XCircle}
        trend="down"
        trendValue="-2 from last month"
        iconColor="text-red-600"
        valueColor="text-red-600 dark:text-red-400"
      />
      <StatCard
        label="Blocked by Policy"
        value={3}
        icon={ShieldAlert}
        description="Security policies enforced"
        iconColor="text-orange-600"
        valueColor="text-orange-600 dark:text-orange-400"
      />
    </MetricsGrid>
  ),
};

// Different Value Types
export const DifferentValues: Story = {
  render: () => (
    <div className="flex flex-col gap-4">
      <StatCard
        label="Success Rate"
        value="99.8%"
        icon={TrendingUp}
        trend="up"
        trendValue="+0.2% from last week"
        iconColor="text-green-600"
      />
      <StatCard
        label="Average Deploy Time"
        value="2.4min"
        description="Across all environments"
        icon={Package}
        iconColor="text-blue-600"
      />
      <StatCard
        label="SLA Uptime"
        value="99.99%"
        description="Last 30 days"
        icon={CheckCircle2}
        iconColor="text-green-600"
      />
    </div>
  ),
};

// MetricsGrid Layouts
export const GridLayouts: Story = {
  render: () => (
    <div className="flex flex-col gap-8 w-full max-w-6xl">
      <div className="space-y-2">
        <h3 className="text-sm font-semibold text-gray-700 dark:text-gray-300">2 Columns</h3>
        <MetricsGrid columns={2}>
          <StatCard label="Critical" value={12} icon={XCircle} iconColor="text-red-600" />
          <StatCard label="High" value={45} icon={AlertTriangle} iconColor="text-orange-600" />
        </MetricsGrid>
      </div>

      <div className="space-y-2">
        <h3 className="text-sm font-semibold text-gray-700 dark:text-gray-300">3 Columns</h3>
        <MetricsGrid columns={3}>
          <StatCard label="Critical" value={12} icon={XCircle} iconColor="text-red-600" />
          <StatCard label="High" value={45} icon={AlertTriangle} iconColor="text-orange-600" />
          <StatCard label="Medium" value={128} icon={ShieldAlert} iconColor="text-yellow-600" />
        </MetricsGrid>
      </div>

      <div className="space-y-2">
        <h3 className="text-sm font-semibold text-gray-700 dark:text-gray-300">4 Columns (Default)</h3>
        <MetricsGrid columns={4}>
          <StatCard label="Critical" value={12} icon={XCircle} iconColor="text-red-600" />
          <StatCard label="High" value={45} icon={AlertTriangle} iconColor="text-orange-600" />
          <StatCard label="Medium" value={128} icon={ShieldAlert} iconColor="text-yellow-600" />
          <StatCard label="Low" value={256} icon={CheckCircle2} iconColor="text-blue-600" />
        </MetricsGrid>
      </div>
    </div>
  ),
};

// Clickable StatCards
export const Clickable: Story = {
  render: () => (
    <MetricsGrid columns={3}>
      <StatCard
        label="Critical Vulnerabilities"
        value={12}
        icon={XCircle}
        iconColor="text-red-600"
        valueColor="text-red-600 dark:text-red-400"
        onClick={() => alert('Navigate to Critical Vulnerabilities')}
      />
      <StatCard
        label="Failed Deployments"
        value={5}
        icon={AlertTriangle}
        iconColor="text-orange-600"
        onClick={() => alert('Navigate to Failed Deployments')}
      />
      <StatCard
        label="Policy Violations"
        value={3}
        icon={ShieldAlert}
        iconColor="text-yellow-600"
        onClick={() => alert('Navigate to Policy Violations')}
      />
    </MetricsGrid>
  ),
};

// Dark Mode
export const DarkMode: Story = {
  render: () => (
    <div className="dark">
      <div className="bg-gray-950 p-8 rounded-lg">
        <MetricsGrid columns={4}>
          <StatCard
            label="Critical"
            value={12}
            icon={XCircle}
            trend="down"
            trendValue="-3 from yesterday"
            iconColor="text-red-600"
            valueColor="text-red-600 dark:text-red-400"
          />
          <StatCard
            label="High"
            value={45}
            icon={AlertTriangle}
            trend="up"
            trendValue="+5 from yesterday"
            iconColor="text-orange-600"
            valueColor="text-orange-600 dark:text-orange-400"
          />
          <StatCard
            label="Medium"
            value={128}
            icon={ShieldAlert}
            iconColor="text-yellow-600"
            valueColor="text-yellow-600 dark:text-yellow-400"
          />
          <StatCard
            label="Resolved"
            value={67}
            icon={CheckCircle2}
            trend="up"
            trendValue="+12 this week"
            iconColor="text-green-600"
            valueColor="text-green-600 dark:text-green-400"
          />
        </MetricsGrid>
      </div>
    </div>
  ),
  parameters: {
    backgrounds: { default: 'dark' },
  },
};

// Complete Dashboard Example
export const DashboardExample: Story = {
  render: () => (
    <div className="w-full max-w-6xl space-y-6">
      <div>
        <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-2">Security Dashboard</h2>
        <p className="text-gray-500 dark:text-gray-400">Overview of your security posture</p>
      </div>

      <MetricsGrid columns={4}>
        <StatCard
          label="Critical Vulnerabilities"
          value={12}
          icon={XCircle}
          trend="down"
          trendValue="-25% from last week"
          iconColor="text-red-600"
          valueColor="text-red-600 dark:text-red-400"
          description="Immediate action required"
        />
        <StatCard
          label="High Severity"
          value={45}
          icon={AlertTriangle}
          trend="up"
          trendValue="+15% from last week"
          iconColor="text-orange-600"
          valueColor="text-orange-600 dark:text-orange-400"
          description="Fix soon"
        />
        <StatCard
          label="Deployments (7d)"
          value={28}
          icon={Package}
          trend="up"
          trendValue="+12% from last week"
          iconColor="text-blue-600"
          description="All environments"
        />
        <StatCard
          label="Policy Compliance"
          value="98.5%"
          icon={CheckCircle2}
          trend="up"
          trendValue="+1.2% from last week"
          iconColor="text-green-600"
          valueColor="text-green-600 dark:text-green-400"
          description="Security policies passed"
        />
      </MetricsGrid>
    </div>
  ),
};
