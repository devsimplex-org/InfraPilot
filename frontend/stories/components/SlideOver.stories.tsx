import type { Meta, StoryObj } from '@storybook/react';
import { SlideOver } from '@/components/ui/SlideOver';
import { SeverityBadge, StatusBadge } from '@/components/ui/Badge';
import { useState } from 'react';
import {
  AlertTriangle,
  Package,
  Calendar,
  User,
  Clock,
  ExternalLink,
  CheckCircle2,
  XCircle,
  Shield,
  Activity,
} from 'lucide-react';

const meta: Meta<typeof SlideOver> = {
  title: 'Components/SlideOver',
  component: SlideOver,
  parameters: {
    layout: 'centered',
  },
  tags: ['autodocs'],
};

export default meta;
type Story = StoryObj<typeof SlideOver>;

// Basic SlideOver
export const Default: Story = {
  render: () => {
    const [isOpen, setIsOpen] = useState(false);

    return (
      <>
        <button
          onClick={() => setIsOpen(true)}
          className="px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700"
        >
          Open SlideOver
        </button>

        <SlideOver isOpen={isOpen} onClose={() => setIsOpen(false)}>
          <SlideOver.Header onClose={() => setIsOpen(false)}>
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
              SlideOver Title
            </h2>
          </SlideOver.Header>
          <SlideOver.Body>
            <p className="text-gray-700 dark:text-gray-300">
              This is a basic SlideOver panel with some content.
            </p>
          </SlideOver.Body>
          <SlideOver.Footer>
            <button
              onClick={() => setIsOpen(false)}
              className="px-4 py-2 bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-200 dark:hover:bg-gray-700"
            >
              Cancel
            </button>
            <button className="px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700">
              Save
            </button>
          </SlideOver.Footer>
        </SlideOver>
      </>
    );
  },
};

// Different sizes
export const Sizes: Story = {
  render: () => {
    const [openSize, setOpenSize] = useState<'sm' | 'md' | 'lg' | 'xl' | null>(null);

    return (
      <div className="flex gap-2">
        <button
          onClick={() => setOpenSize('sm')}
          className="px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700"
        >
          Small
        </button>
        <button
          onClick={() => setOpenSize('md')}
          className="px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700"
        >
          Medium
        </button>
        <button
          onClick={() => setOpenSize('lg')}
          className="px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700"
        >
          Large
        </button>
        <button
          onClick={() => setOpenSize('xl')}
          className="px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700"
        >
          Extra Large
        </button>

        <SlideOver
          isOpen={openSize !== null}
          onClose={() => setOpenSize(null)}
          size={openSize || 'md'}
        >
          <SlideOver.Header onClose={() => setOpenSize(null)}>
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
              {openSize?.toUpperCase()} Size
            </h2>
          </SlideOver.Header>
          <SlideOver.Body>
            <p className="text-gray-700 dark:text-gray-300">
              This SlideOver is using the <strong>{openSize}</strong> size variant.
            </p>
          </SlideOver.Body>
        </SlideOver>
      </div>
    );
  },
};

// With form
export const WithForm: Story = {
  render: () => {
    const [isOpen, setIsOpen] = useState(false);

    return (
      <>
        <button
          onClick={() => setIsOpen(true)}
          className="px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700"
        >
          Add User
        </button>

        <SlideOver isOpen={isOpen} onClose={() => setIsOpen(false)}>
          <SlideOver.Header onClose={() => setIsOpen(false)}>
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
              Add New User
            </h2>
          </SlideOver.Header>
          <SlideOver.Body>
            <form className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Name
                </label>
                <input
                  type="text"
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:ring-2 focus:ring-primary-500 focus:border-transparent"
                  placeholder="John Doe"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Email
                </label>
                <input
                  type="email"
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:ring-2 focus:ring-primary-500 focus:border-transparent"
                  placeholder="john@example.com"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Role
                </label>
                <select className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:ring-2 focus:ring-primary-500 focus:border-transparent">
                  <option>Admin</option>
                  <option>Developer</option>
                  <option>Viewer</option>
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Bio
                </label>
                <textarea
                  rows={4}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:ring-2 focus:ring-primary-500 focus:border-transparent"
                  placeholder="Tell us about yourself..."
                />
              </div>
            </form>
          </SlideOver.Body>
          <SlideOver.Footer>
            <button
              onClick={() => setIsOpen(false)}
              className="px-4 py-2 bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-200 dark:hover:bg-gray-700"
            >
              Cancel
            </button>
            <button className="px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700">
              Add User
            </button>
          </SlideOver.Footer>
        </SlideOver>
      </>
    );
  },
};

// Footer alignments
export const FooterAlignments: Story = {
  render: () => {
    const [align, setAlign] = useState<'left' | 'center' | 'right' | 'between' | null>(null);

    return (
      <div className="flex gap-2">
        <button
          onClick={() => setAlign('left')}
          className="px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700"
        >
          Left
        </button>
        <button
          onClick={() => setAlign('center')}
          className="px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700"
        >
          Center
        </button>
        <button
          onClick={() => setAlign('right')}
          className="px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700"
        >
          Right
        </button>
        <button
          onClick={() => setAlign('between')}
          className="px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700"
        >
          Between
        </button>

        <SlideOver isOpen={align !== null} onClose={() => setAlign(null)}>
          <SlideOver.Header onClose={() => setAlign(null)}>
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
              Footer Alignment: {align}
            </h2>
          </SlideOver.Header>
          <SlideOver.Body>
            <p className="text-gray-700 dark:text-gray-300">
              Footer buttons are aligned to the <strong>{align}</strong>.
            </p>
          </SlideOver.Body>
          <SlideOver.Footer align={align || 'right'}>
            <button className="px-4 py-2 bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-200 dark:hover:bg-gray-700">
              Cancel
            </button>
            <button className="px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700">
              Save
            </button>
          </SlideOver.Footer>
        </SlideOver>
      </div>
    );
  },
};

// Real-world: Vulnerability Details
export const VulnerabilityDetails: Story = {
  render: () => {
    const [isOpen, setIsOpen] = useState(false);

    const vulnerability = {
      cve_id: 'CVE-2024-12345',
      package_name: 'openssl',
      version: '3.0.7',
      severity: 'critical' as const,
      score: 9.8,
      description: 'A critical vulnerability in OpenSSL allows remote attackers to execute arbitrary code through a specially crafted SSL/TLS handshake.',
      discovered_at: '2024-01-15T10:30:00Z',
      published_at: '2024-01-14T08:00:00Z',
      fixed_version: '3.0.8',
      affected_deployments: [
        { name: 'production-api-v2', environment: 'production' },
        { name: 'staging-web-app', environment: 'staging' },
        { name: 'dev-api-gateway', environment: 'development' },
      ],
      references: [
        'https://nvd.nist.gov/vuln/detail/CVE-2024-12345',
        'https://www.openssl.org/news/secadv/20240114.txt',
      ],
    };

    return (
      <>
        <button
          onClick={() => setIsOpen(true)}
          className="px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700"
        >
          View Vulnerability Details
        </button>

        <SlideOver isOpen={isOpen} onClose={() => setIsOpen(false)} size="lg">
          <SlideOver.Header onClose={() => setIsOpen(false)}>
            <div>
              <div className="flex items-center gap-3">
                <AlertTriangle className="h-6 w-6 text-red-600" />
                <h2 className="text-xl font-semibold text-gray-900 dark:text-white">
                  {vulnerability.cve_id}
                </h2>
                <SeverityBadge severity={vulnerability.severity} />
              </div>
              <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
                {vulnerability.package_name} @ {vulnerability.version}
              </p>
            </div>
          </SlideOver.Header>

          <SlideOver.Body>
            <div className="space-y-6">
              {/* Overview */}
              <div>
                <h3 className="text-sm font-semibold text-gray-900 dark:text-white uppercase tracking-wide mb-3">
                  Overview
                </h3>
                <div className="bg-gray-50 dark:bg-gray-800 rounded-lg p-4">
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <p className="text-xs text-gray-500 dark:text-gray-400 mb-1">CVSS Score</p>
                      <p className="text-lg font-bold text-red-600 dark:text-red-400">
                        {vulnerability.score}
                      </p>
                    </div>
                    <div>
                      <p className="text-xs text-gray-500 dark:text-gray-400 mb-1">Fixed In</p>
                      <p className="text-sm font-medium text-gray-900 dark:text-white">
                        {vulnerability.fixed_version}
                      </p>
                    </div>
                    <div>
                      <p className="text-xs text-gray-500 dark:text-gray-400 mb-1">Published</p>
                      <p className="text-sm text-gray-700 dark:text-gray-300">
                        {new Date(vulnerability.published_at).toLocaleDateString()}
                      </p>
                    </div>
                    <div>
                      <p className="text-xs text-gray-500 dark:text-gray-400 mb-1">Discovered</p>
                      <p className="text-sm text-gray-700 dark:text-gray-300">
                        {new Date(vulnerability.discovered_at).toLocaleDateString()}
                      </p>
                    </div>
                  </div>
                </div>
              </div>

              {/* Description */}
              <div>
                <h3 className="text-sm font-semibold text-gray-900 dark:text-white uppercase tracking-wide mb-3">
                  Description
                </h3>
                <p className="text-sm text-gray-700 dark:text-gray-300 leading-relaxed">
                  {vulnerability.description}
                </p>
              </div>

              {/* Affected Deployments */}
              <div>
                <h3 className="text-sm font-semibold text-gray-900 dark:text-white uppercase tracking-wide mb-3">
                  Affected Deployments ({vulnerability.affected_deployments.length})
                </h3>
                <div className="space-y-2">
                  {vulnerability.affected_deployments.map((deployment, index) => (
                    <div
                      key={index}
                      className="flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-800 rounded-lg"
                    >
                      <div className="flex items-center gap-2">
                        <Package className="h-4 w-4 text-gray-400" />
                        <span className="text-sm font-medium text-gray-900 dark:text-white">
                          {deployment.name}
                        </span>
                      </div>
                      <span className="text-xs text-gray-500 dark:text-gray-400">
                        {deployment.environment}
                      </span>
                    </div>
                  ))}
                </div>
              </div>

              {/* References */}
              <div>
                <h3 className="text-sm font-semibold text-gray-900 dark:text-white uppercase tracking-wide mb-3">
                  References
                </h3>
                <div className="space-y-2">
                  {vulnerability.references.map((ref, index) => (
                    <a
                      key={index}
                      href={ref}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="flex items-center gap-2 text-sm text-primary-600 dark:text-primary-400 hover:underline"
                    >
                      <ExternalLink className="h-3 w-3" />
                      {ref}
                    </a>
                  ))}
                </div>
              </div>
            </div>
          </SlideOver.Body>

          <SlideOver.Footer align="between">
            <button
              onClick={() => setIsOpen(false)}
              className="px-4 py-2 bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-200 dark:hover:bg-gray-700"
            >
              Close
            </button>
            <div className="flex gap-2">
              <button className="px-4 py-2 bg-yellow-600 text-white rounded-lg hover:bg-yellow-700">
                Ignore
              </button>
              <button className="px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700">
                Create Fix Task
              </button>
            </div>
          </SlideOver.Footer>
        </SlideOver>
      </>
    );
  },
};

// Real-world: Deployment Details
export const DeploymentDetails: Story = {
  render: () => {
    const [isOpen, setIsOpen] = useState(false);

    const deployment = {
      id: 'dep_123456',
      name: 'production-api-v2',
      environment: 'production',
      status: 'healthy' as const,
      version: 'v2.4.1',
      deployed_at: '2024-01-15T08:00:00Z',
      deployed_by: 'john@example.com',
      namespace: 'production',
      replicas: { desired: 3, ready: 3 },
      vulnerabilities: { critical: 0, high: 2, medium: 5, low: 12 },
      policy_compliance: 'passed',
      resources: {
        cpu: { requested: '500m', limit: '1000m', usage: '450m' },
        memory: { requested: '512Mi', limit: '1Gi', usage: '620Mi' },
      },
    };

    return (
      <>
        <button
          onClick={() => setIsOpen(true)}
          className="px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700"
        >
          View Deployment Details
        </button>

        <SlideOver isOpen={isOpen} onClose={() => setIsOpen(false)} size="xl">
          <SlideOver.Header onClose={() => setIsOpen(false)}>
            <div>
              <div className="flex items-center gap-3">
                <Package className="h-6 w-6 text-primary-600" />
                <h2 className="text-xl font-semibold text-gray-900 dark:text-white">
                  {deployment.name}
                </h2>
                <StatusBadge status={deployment.status} />
              </div>
              <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
                {deployment.environment} • {deployment.version}
              </p>
            </div>
          </SlideOver.Header>

          <SlideOver.Body>
            <div className="space-y-6">
              {/* Status Overview */}
              <div className="grid grid-cols-3 gap-4">
                <div className="bg-green-50 dark:bg-green-900/20 rounded-lg p-4">
                  <div className="flex items-center gap-2 mb-2">
                    <CheckCircle2 className="h-5 w-5 text-green-600 dark:text-green-400" />
                    <p className="text-xs font-semibold text-green-900 dark:text-green-300 uppercase">
                      Status
                    </p>
                  </div>
                  <p className="text-2xl font-bold text-green-600 dark:text-green-400">
                    Healthy
                  </p>
                </div>

                <div className="bg-blue-50 dark:bg-blue-900/20 rounded-lg p-4">
                  <div className="flex items-center gap-2 mb-2">
                    <Activity className="h-5 w-5 text-blue-600 dark:text-blue-400" />
                    <p className="text-xs font-semibold text-blue-900 dark:text-blue-300 uppercase">
                      Replicas
                    </p>
                  </div>
                  <p className="text-2xl font-bold text-blue-600 dark:text-blue-400">
                    {deployment.replicas.ready}/{deployment.replicas.desired}
                  </p>
                </div>

                <div className="bg-purple-50 dark:bg-purple-900/20 rounded-lg p-4">
                  <div className="flex items-center gap-2 mb-2">
                    <Shield className="h-5 w-5 text-purple-600 dark:text-purple-400" />
                    <p className="text-xs font-semibold text-purple-900 dark:text-purple-300 uppercase">
                      Policy
                    </p>
                  </div>
                  <p className="text-2xl font-bold text-purple-600 dark:text-purple-400">
                    Passed
                  </p>
                </div>
              </div>

              {/* Deployment Info */}
              <div>
                <h3 className="text-sm font-semibold text-gray-900 dark:text-white uppercase tracking-wide mb-3">
                  Deployment Information
                </h3>
                <div className="bg-gray-50 dark:bg-gray-800 rounded-lg p-4 space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-gray-500 dark:text-gray-400">ID</span>
                    <span className="text-sm font-mono text-gray-900 dark:text-white">
                      {deployment.id}
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-gray-500 dark:text-gray-400">Namespace</span>
                    <span className="text-sm font-medium text-gray-900 dark:text-white">
                      {deployment.namespace}
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-gray-500 dark:text-gray-400">Deployed By</span>
                    <span className="text-sm text-gray-900 dark:text-white">
                      {deployment.deployed_by}
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-gray-500 dark:text-gray-400">Deployed At</span>
                    <span className="text-sm text-gray-900 dark:text-white">
                      {new Date(deployment.deployed_at).toLocaleString()}
                    </span>
                  </div>
                </div>
              </div>

              {/* Vulnerabilities */}
              <div>
                <h3 className="text-sm font-semibold text-gray-900 dark:text-white uppercase tracking-wide mb-3">
                  Vulnerabilities
                </h3>
                <div className="grid grid-cols-4 gap-3">
                  <div className="bg-red-50 dark:bg-red-900/20 rounded-lg p-3 text-center">
                    <p className="text-2xl font-bold text-red-600 dark:text-red-400">
                      {deployment.vulnerabilities.critical}
                    </p>
                    <p className="text-xs text-red-700 dark:text-red-300 mt-1">Critical</p>
                  </div>
                  <div className="bg-orange-50 dark:bg-orange-900/20 rounded-lg p-3 text-center">
                    <p className="text-2xl font-bold text-orange-600 dark:text-orange-400">
                      {deployment.vulnerabilities.high}
                    </p>
                    <p className="text-xs text-orange-700 dark:text-orange-300 mt-1">High</p>
                  </div>
                  <div className="bg-yellow-50 dark:bg-yellow-900/20 rounded-lg p-3 text-center">
                    <p className="text-2xl font-bold text-yellow-600 dark:text-yellow-400">
                      {deployment.vulnerabilities.medium}
                    </p>
                    <p className="text-xs text-yellow-700 dark:text-yellow-300 mt-1">Medium</p>
                  </div>
                  <div className="bg-blue-50 dark:bg-blue-900/20 rounded-lg p-3 text-center">
                    <p className="text-2xl font-bold text-blue-600 dark:text-blue-400">
                      {deployment.vulnerabilities.low}
                    </p>
                    <p className="text-xs text-blue-700 dark:text-blue-300 mt-1">Low</p>
                  </div>
                </div>
              </div>

              {/* Resources */}
              <div>
                <h3 className="text-sm font-semibold text-gray-900 dark:text-white uppercase tracking-wide mb-3">
                  Resource Usage
                </h3>
                <div className="space-y-4">
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-sm font-medium text-gray-700 dark:text-gray-300">
                        CPU
                      </span>
                      <span className="text-sm text-gray-500 dark:text-gray-400">
                        {deployment.resources.cpu.usage} / {deployment.resources.cpu.limit}
                      </span>
                    </div>
                    <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                      <div
                        className="bg-primary-600 h-2 rounded-full"
                        style={{ width: '45%' }}
                      />
                    </div>
                  </div>
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-sm font-medium text-gray-700 dark:text-gray-300">
                        Memory
                      </span>
                      <span className="text-sm text-gray-500 dark:text-gray-400">
                        {deployment.resources.memory.usage} / {deployment.resources.memory.limit}
                      </span>
                    </div>
                    <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                      <div
                        className="bg-primary-600 h-2 rounded-full"
                        style={{ width: '60%' }}
                      />
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </SlideOver.Body>

          <SlideOver.Footer align="between">
            <button
              onClick={() => setIsOpen(false)}
              className="px-4 py-2 bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-200 dark:hover:bg-gray-700"
            >
              Close
            </button>
            <div className="flex gap-2">
              <button className="px-4 py-2 bg-yellow-600 text-white rounded-lg hover:bg-yellow-700">
                View Logs
              </button>
              <button className="px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700">
                Rollback
              </button>
            </div>
          </SlideOver.Footer>
        </SlideOver>
      </>
    );
  },
};

// Dark Mode
export const DarkMode: Story = {
  render: () => {
    const [isOpen, setIsOpen] = useState(false);

    return (
      <div className="dark">
        <div className="bg-gray-950 p-8 rounded-lg">
          <button
            onClick={() => setIsOpen(true)}
            className="px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700"
          >
            Open Dark Mode SlideOver
          </button>

          <SlideOver isOpen={isOpen} onClose={() => setIsOpen(false)}>
            <SlideOver.Header onClose={() => setIsOpen(false)}>
              <h2 className="text-lg font-semibold text-white">Dark Mode SlideOver</h2>
            </SlideOver.Header>
            <SlideOver.Body>
              <p className="text-gray-300 mb-4">
                This SlideOver demonstrates dark mode styling with proper contrast and
                accessibility.
              </p>
              <div className="bg-gray-800 rounded-lg p-4">
                <p className="text-sm text-gray-400">
                  Content boxes and elements are properly styled for dark mode.
                </p>
              </div>
            </SlideOver.Body>
            <SlideOver.Footer>
              <button
                onClick={() => setIsOpen(false)}
                className="px-4 py-2 bg-gray-800 text-gray-300 rounded-lg hover:bg-gray-700"
              >
                Cancel
              </button>
              <button className="px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700">
                Save
              </button>
            </SlideOver.Footer>
          </SlideOver>
        </div>
      </div>
    );
  },
  parameters: {
    backgrounds: { default: 'dark' },
  },
};
