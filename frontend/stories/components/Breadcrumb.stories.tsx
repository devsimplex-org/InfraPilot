import type { Meta, StoryObj } from '@storybook/react';
import { Breadcrumb } from '@/components/ui/Breadcrumb';
import { Slash } from 'lucide-react';

const meta: Meta<typeof Breadcrumb> = {
  title: 'Components/Breadcrumb',
  component: Breadcrumb,
  parameters: {
    layout: 'padded',
  },
  tags: ['autodocs'],
};

export default meta;
type Story = StoryObj<typeof Breadcrumb>;

// Basic breadcrumb
export const Default: Story = {
  args: {
    items: [
      { label: 'Deployments', href: '/deployments' },
      { label: 'production-api-v2', href: '/deployments/prod-api' },
      { label: 'Details' },
    ],
  },
};

// Without home
export const WithoutHome: Story = {
  args: {
    showHome: false,
    items: [
      { label: 'Deploy', href: '/deploy' },
      { label: 'Deployments', href: '/deployments' },
      { label: 'production-api-v2' },
    ],
  },
};

// Simple (2 levels)
export const Simple: Story = {
  args: {
    items: [
      { label: 'Deployments', href: '/deployments' },
      { label: 'production-api-v2' },
    ],
  },
};

// Deep (4 levels)
export const Deep: Story = {
  args: {
    items: [
      { label: 'Deploy', href: '/deploy' },
      { label: 'Deployments', href: '/deployments' },
      { label: 'production-api-v2', href: '/deployments/prod-api' },
      { label: 'Version #842' },
    ],
  },
};

// Custom separator
export const CustomSeparator: Story = {
  args: {
    items: [
      { label: 'Deployments', href: '/deployments' },
      { label: 'production-api-v2', href: '/deployments/prod-api' },
      { label: 'Details' },
    ],
    separator: <Slash className="h-4 w-4" />,
  },
};

// Real-world: Deployment details
export const DeploymentDetails: Story = {
  args: {
    items: [
      { label: 'Deployments', href: '/deployments' },
      { label: 'production-api-v2', href: '/deployments/prod-api' },
      { label: 'Production', href: '/deployments/prod-api/production' },
      { label: 'Deployment #842' },
    ],
  },
};

// Real-world: Vulnerability details
export const VulnerabilityDetails: Story = {
  args: {
    items: [
      { label: 'Vulnerabilities', href: '/vulnerabilities' },
      { label: 'CVE-2024-12345' },
    ],
  },
};

// Real-world: Policy details
export const PolicyDetails: Story = {
  args: {
    items: [
      { label: 'Policies', href: '/policies' },
      { label: 'Production Security Requirements', href: '/policies/prod-sec' },
      { label: 'Edit' },
    ],
  },
};

// Real-world: Runtime event
export const RuntimeEvent: Story = {
  args: {
    items: [
      { label: 'Runtime Security', href: '/runtime-security' },
      { label: 'Drift Events', href: '/runtime-security/drift' },
      { label: 'Event #12345' },
    ],
  },
};

// Real-world: Exception review
export const ExceptionReview: Story = {
  args: {
    items: [
      { label: 'Risk Exceptions', href: '/exceptions' },
      { label: 'CVE-2024-12345', href: '/exceptions/cve-2024-12345' },
      { label: 'Review' },
    ],
  },
};

// Real-world: Team member
export const TeamMember: Story = {
  args: {
    items: [
      { label: 'Teams', href: '/teams' },
      { label: 'john@example.com' },
    ],
  },
};

// In page header
export const InPageHeader: Story = {
  render: () => (
    <div className="space-y-4">
      <Breadcrumb
        items={[
          { label: 'Deployments', href: '/deployments' },
          { label: 'production-api-v2', href: '/deployments/prod-api' },
          { label: 'Production' },
        ]}
      />
      <div>
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
          production-api-v2
        </h1>
        <p className="text-sm text-gray-500 dark:text-gray-400 mt-2">
          Deployed 2 hours ago in production environment
        </p>
      </div>
    </div>
  ),
};

// Dark Mode
export const DarkMode: Story = {
  render: () => (
    <div className="dark">
      <div className="bg-gray-950 p-8 rounded-lg space-y-6">
        <div>
          <h3 className="text-sm font-semibold text-gray-400 mb-3">With Home</h3>
          <Breadcrumb
            items={[
              { label: 'Deployments', href: '/deployments' },
              { label: 'production-api-v2', href: '/deployments/prod-api' },
              { label: 'Details' },
            ]}
          />
        </div>
        <div>
          <h3 className="text-sm font-semibold text-gray-400 mb-3">Without Home</h3>
          <Breadcrumb
            showHome={false}
            items={[
              { label: 'Deploy', href: '/deploy' },
              { label: 'Deployments', href: '/deployments' },
              { label: 'production-api-v2' },
            ]}
          />
        </div>
        <div>
          <h3 className="text-sm font-semibold text-gray-400 mb-3">In Page Context</h3>
          <Breadcrumb
            items={[
              { label: 'Vulnerabilities', href: '/vulnerabilities' },
              { label: 'CVE-2024-12345' },
            ]}
          />
          <h1 className="text-2xl font-bold text-white mt-4">CVE-2024-12345</h1>
          <p className="text-sm text-gray-400 mt-2">
            Critical severity OpenSSL vulnerability
          </p>
        </div>
      </div>
    </div>
  ),
  parameters: {
    backgrounds: { default: 'dark' },
  },
};
