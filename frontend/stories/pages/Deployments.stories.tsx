import type { Meta, StoryObj } from '@storybook/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import DeploymentsPage from '@/app/(dashboard)/deployments-refactored/page';
import type { Deployment, ScanResult } from '@/lib/api';

/**
 * Deployments Page
 *
 * The deployments page provides comprehensive management and monitoring of all deployments
 * across environments. It includes security scanning, vulnerability tracking, SBOM generation,
 * and policy compliance checking.
 *
 * Features:
 * - Deployment listing with filtering and search
 * - Real-time status monitoring
 * - Security scan results with vulnerability distribution
 * - SBOM (Software Bill of Materials) access
 * - Policy decision tracking (allow/warn/deny)
 * - Git and CI/CD integration information
 */
const meta: Meta<typeof DeploymentsPage> = {
  title: 'Pages/Deployments',
  component: DeploymentsPage,
  parameters: {
    layout: 'fullscreen',
    docs: {
      description: {
        component: 'The deployments page shows all deployments with security scanning and policy enforcement.',
      },
    },
  },
};

export default meta;
type Story = StoryObj<typeof DeploymentsPage>;

/**
 * Mock Data Helpers
 */
const createMockAgent = (overrides = {}) => ({
  id: 'agent-1',
  org_id: 'org-1',
  name: 'Production Agent',
  hostname: 'prod-server-01',
  status: 'active' as const,
  version: '1.0.0',
  last_seen_at: new Date().toISOString(),
  created_at: new Date(Date.now() - 86400000 * 30).toISOString(),
  ...overrides,
});

const createMockDeployment = (id: string, overrides: Partial<Deployment> = {}): Deployment => ({
  id,
  agent_id: 'agent-1',
  service_name: 'production-api',
  environment: 'production',
  image_repository: 'myorg/api',
  image_tag: 'v2.3.1',
  image_digest: 'sha256:abcd1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab',
  status: 'running',
  status_message: null,
  scan_result_id: `scan-${id}`,
  sbom_id: `sbom-${id}`,
  policy_decision: 'allow',
  policy_reason: null,
  git_repo: 'https://github.com/myorg/api',
  git_branch: 'main',
  git_commit: 'abc1234567890def1234567890abc1234567890d',
  ci_provider: 'github-actions',
  ci_pipeline_id: '12345678',
  ci_build_url: 'https://github.com/myorg/api/actions/runs/12345678',
  deployed_at: new Date(Date.now() - 86400000 * 2).toISOString(),
  created_at: new Date(Date.now() - 86400000 * 3).toISOString(),
  ...overrides,
});

const createMockScanResult = (id: string, overrides = {}): ScanResult => ({
  id,
  deployment_id: id.replace('scan-', ''),
  scanner_name: 'trivy',
  scanner_version: '0.48.1',
  total_count: 15,
  critical_count: 2,
  high_count: 5,
  medium_count: 6,
  low_count: 2,
  fixable_count: 10,
  scanned_at: new Date(Date.now() - 86400000 * 2).toISOString(),
  scan_duration_ms: 12500,
  ...overrides,
});

const createMockVulnerability = (id: string, severity: string, overrides = {}) => ({
  id,
  scan_result_id: 'scan-1',
  cve_id: `CVE-2024-${10000 + parseInt(id.split('-')[1])}`,
  severity: severity.toUpperCase(),
  cvss_score: severity === 'critical' ? 9.5 : severity === 'high' ? 7.8 : severity === 'medium' ? 5.2 : 3.1,
  title: `${severity.charAt(0).toUpperCase() + severity.slice(1)} vulnerability in package`,
  description: `This is a ${severity} severity vulnerability that could potentially impact system security.`,
  package_name: severity === 'critical' ? 'openssl' : severity === 'high' ? 'libcurl' : severity === 'medium' ? 'zlib' : 'util-linux',
  package_version: '1.0.0',
  fixed_version: severity !== 'low' ? '1.1.0' : null,
  fix_available: severity !== 'low',
  ...overrides,
});

const createMockSBOM = (id: string, overrides = {}) => ({
  id,
  deployment_id: id.replace('sbom-', ''),
  format: 'cyclonedx',
  spec_version: '1.5',
  generator_name: 'syft',
  generator_version: '0.100.0',
  total_packages: 245,
  os_packages: 180,
  library_packages: 65,
  created_at: new Date(Date.now() - 86400000 * 2).toISOString(),
  ...overrides,
});

/**
 * Default State - Healthy Deployments
 *
 * Shows a typical view with multiple healthy deployments:
 * - All deployments running successfully
 * - Some vulnerabilities but all within acceptable limits
 * - Policy compliance passing
 */
export const Default: Story = {
  decorators: [
    (Story) => {
      const queryClient = new QueryClient({
        defaultOptions: {
          queries: {
            retry: false,
            staleTime: Infinity,
            queryFn: async ({ queryKey }) => {
              const key = JSON.stringify(queryKey);

              if (key.includes('agents') && !key.includes('deployments')) {
                return [createMockAgent()];
              }
              if (key.includes('deployments')) {
                return [
                  createMockDeployment('deploy-1', {
                    service_name: 'production-api',
                    environment: 'production',
                    image_tag: 'v2.3.1',
                  }),
                  createMockDeployment('deploy-2', {
                    service_name: 'production-web',
                    environment: 'production',
                    image_repository: 'myorg/web',
                    image_tag: 'v1.8.5',
                  }),
                  createMockDeployment('deploy-3', {
                    service_name: 'staging-api',
                    environment: 'staging',
                    image_tag: 'v2.4.0-rc1',
                    policy_decision: 'warn',
                    policy_reason: 'Contains 1 high severity vulnerability',
                  }),
                ];
              }
              return null;
            },
          },
        },
      });

      return (
        <QueryClientProvider client={queryClient}>
          <div className="min-h-screen bg-gray-50 dark:bg-gray-950 p-6">
            <Story />
          </div>
        </QueryClientProvider>
      );
    },
  ],
};

/**
 * With Vulnerabilities
 *
 * Demonstrates deployments with various vulnerability states:
 * - Critical vulnerabilities in one deployment
 * - High vulnerabilities in another
 * - Clean deployment with no issues
 */
export const WithVulnerabilities: Story = {
  decorators: [
    (Story) => {
      const queryClient = new QueryClient({
        defaultOptions: {
          queries: {
            retry: false,
            staleTime: Infinity,
            queryFn: async ({ queryKey }) => {
              const key = JSON.stringify(queryKey);

              if (key.includes('agents') && !key.includes('deployments')) {
                return [createMockAgent()];
              }
              if (key.includes('deployments')) {
                return [
                  createMockDeployment('deploy-1', {
                    service_name: 'production-api',
                    environment: 'production',
                    status: 'running',
                    policy_decision: 'deny',
                    policy_reason: 'Blocked: 5 critical vulnerabilities detected',
                  }),
                  createMockDeployment('deploy-2', {
                    service_name: 'staging-api',
                    environment: 'staging',
                    image_tag: 'v2.4.0',
                    policy_decision: 'warn',
                    policy_reason: '12 high severity vulnerabilities',
                  }),
                  createMockDeployment('deploy-3', {
                    service_name: 'development-api',
                    environment: 'development',
                    image_tag: 'v2.5.0-dev',
                    policy_decision: 'allow',
                    policy_reason: null,
                  }),
                ];
              }
              if (key.includes('scanResult')) {
                return createMockScanResult('scan-1', {
                  total_count: 45,
                  critical_count: 5,
                  high_count: 12,
                  medium_count: 18,
                  low_count: 10,
                  fixable_count: 35,
                });
              }
              if (key.includes('vulnerabilities')) {
                return [
                  createMockVulnerability('vuln-1', 'critical'),
                  createMockVulnerability('vuln-2', 'critical'),
                  createMockVulnerability('vuln-3', 'high'),
                  createMockVulnerability('vuln-4', 'high'),
                  createMockVulnerability('vuln-5', 'medium'),
                ];
              }
              if (key.includes('sboms')) {
                return [createMockSBOM('sbom-1')];
              }
              return null;
            },
          },
        },
      });

      return (
        <QueryClientProvider client={queryClient}>
          <div className="min-h-screen bg-gray-50 dark:bg-gray-950 p-6">
            <Story />
          </div>
        </QueryClientProvider>
      );
    },
  ],
};

/**
 * Failed Deployment
 *
 * Shows deployments in various failure states:
 * - Deployment failed
 * - Policy blocked deployment
 * - Scanning state
 */
export const FailedDeployment: Story = {
  decorators: [
    (Story) => {
      const queryClient = new QueryClient({
        defaultOptions: {
          queries: {
            retry: false,
            staleTime: Infinity,
            queryFn: async ({ queryKey }) => {
              const key = JSON.stringify(queryKey);

              if (key.includes('agents') && !key.includes('deployments')) {
                return [createMockAgent()];
              }
              if (key.includes('deployments')) {
                return [
                  createMockDeployment('deploy-1', {
                    service_name: 'production-api',
                    environment: 'production',
                    status: 'failed',
                    status_message: 'Container failed health check after 3 retries',
                    policy_decision: 'allow',
                  }),
                  createMockDeployment('deploy-2', {
                    service_name: 'staging-api',
                    environment: 'staging',
                    status: 'running',
                    policy_decision: 'deny',
                    policy_reason: 'Critical vulnerabilities: CVE-2024-12345, CVE-2024-12346',
                  }),
                  createMockDeployment('deploy-3', {
                    service_name: 'development-api',
                    environment: 'development',
                    status: 'scanning',
                    status_message: 'Security scan in progress...',
                    scan_result_id: null,
                  }),
                ];
              }
              return null;
            },
          },
        },
      });

      return (
        <QueryClientProvider client={queryClient}>
          <div className="min-h-screen bg-gray-50 dark:bg-gray-950 p-6">
            <Story />
          </div>
        </QueryClientProvider>
      );
    },
  ],
};

/**
 * Loading State
 *
 * Shows the loading state while deployments are being fetched.
 */
export const Loading: Story = {
  decorators: [
    (Story) => {
      const queryClient = new QueryClient({
        defaultOptions: {
          queries: {
            retry: false,
            staleTime: Infinity,
            queryFn: async ({ queryKey }) => {
              const key = JSON.stringify(queryKey);

              if (key.includes('agents') && !key.includes('deployments')) {
                return [createMockAgent()];
              }
              if (key.includes('deployments')) {
                // Return pending promise
                return new Promise(() => {});
              }
              return null;
            },
          },
        },
      });

      return (
        <QueryClientProvider client={queryClient}>
          <div className="min-h-screen bg-gray-50 dark:bg-gray-950 p-6">
            <Story />
          </div>
        </QueryClientProvider>
      );
    },
  ],
};

/**
 * Empty State - No Deployments
 *
 * Shows the empty state when no deployments exist yet.
 */
export const EmptyState: Story = {
  decorators: [
    (Story) => {
      const queryClient = new QueryClient({
        defaultOptions: {
          queries: {
            retry: false,
            staleTime: Infinity,
            queryFn: async ({ queryKey }) => {
              const key = JSON.stringify(queryKey);

              if (key.includes('agents') && !key.includes('deployments')) {
                return [createMockAgent()];
              }
              if (key.includes('deployments')) {
                return [];
              }
              return null;
            },
          },
        },
      });

      return (
        <QueryClientProvider client={queryClient}>
          <div className="min-h-screen bg-gray-50 dark:bg-gray-950 p-6">
            <Story />
          </div>
        </QueryClientProvider>
      );
    },
  ],
};

/**
 * No Active Agents
 *
 * Shows the state when no agents are available to fetch deployments from.
 */
export const NoActiveAgents: Story = {
  decorators: [
    (Story) => {
      const queryClient = new QueryClient({
        defaultOptions: {
          queries: {
            retry: false,
            staleTime: Infinity,
            queryFn: async ({ queryKey }) => {
              const key = JSON.stringify(queryKey);

              if (key.includes('agents')) {
                return [];
              }
              return null;
            },
          },
        },
      });

      return (
        <QueryClientProvider client={queryClient}>
          <div className="min-h-screen bg-gray-50 dark:bg-gray-950 p-6">
            <Story />
          </div>
        </QueryClientProvider>
      );
    },
  ],
};

/**
 * Multiple Environments
 *
 * Demonstrates deployments across multiple environments:
 * - Production (stable)
 * - Staging (testing)
 * - Development (active development)
 */
export const MultipleEnvironments: Story = {
  decorators: [
    (Story) => {
      const queryClient = new QueryClient({
        defaultOptions: {
          queries: {
            retry: false,
            staleTime: Infinity,
            queryFn: async ({ queryKey }) => {
              const key = JSON.stringify(queryKey);

              if (key.includes('agents') && !key.includes('deployments')) {
                return [
                  createMockAgent(),
                  createMockAgent({ id: 'agent-2', name: 'Staging Agent' }),
                ];
              }
              if (key.includes('deployments')) {
                return [
                  createMockDeployment('deploy-1', {
                    service_name: 'production-api',
                    environment: 'production',
                    image_tag: 'v2.3.1',
                    status: 'running',
                  }),
                  createMockDeployment('deploy-2', {
                    service_name: 'production-web',
                    environment: 'production',
                    image_repository: 'myorg/web',
                    image_tag: 'v1.8.5',
                    status: 'running',
                  }),
                  createMockDeployment('deploy-3', {
                    service_name: 'staging-api',
                    environment: 'staging',
                    image_tag: 'v2.4.0-rc1',
                    status: 'running',
                    policy_decision: 'warn',
                  }),
                  createMockDeployment('deploy-4', {
                    service_name: 'staging-web',
                    environment: 'staging',
                    image_repository: 'myorg/web',
                    image_tag: 'v1.9.0-rc2',
                    status: 'running',
                  }),
                  createMockDeployment('deploy-5', {
                    service_name: 'development-api',
                    environment: 'development',
                    image_tag: 'v2.5.0-dev',
                    status: 'deploying',
                    status_message: 'Deploying new version...',
                  }),
                ];
              }
              return null;
            },
          },
        },
      });

      return (
        <QueryClientProvider client={queryClient}>
          <div className="min-h-screen bg-gray-50 dark:bg-gray-950 p-6">
            <Story />
          </div>
        </QueryClientProvider>
      );
    },
  ],
};

/**
 * Clean Scan - No Vulnerabilities
 *
 * Shows a deployment that passed security scanning with zero vulnerabilities.
 * This represents the ideal state after successful remediation.
 */
export const CleanScan: Story = {
  decorators: [
    (Story) => {
      const queryClient = new QueryClient({
        defaultOptions: {
          queries: {
            retry: false,
            staleTime: Infinity,
            queryFn: async ({ queryKey }) => {
              const key = JSON.stringify(queryKey);

              if (key.includes('agents') && !key.includes('deployments')) {
                return [createMockAgent()];
              }
              if (key.includes('deployments')) {
                return [
                  createMockDeployment('deploy-1', {
                    service_name: 'production-api',
                    environment: 'production',
                    image_tag: 'v2.3.1',
                    status: 'running',
                    policy_decision: 'allow',
                  }),
                ];
              }
              if (key.includes('scanResult')) {
                return createMockScanResult('scan-1', {
                  total_count: 0,
                  critical_count: 0,
                  high_count: 0,
                  medium_count: 0,
                  low_count: 0,
                  fixable_count: 0,
                });
              }
              if (key.includes('vulnerabilities')) {
                return [];
              }
              if (key.includes('sboms')) {
                return [createMockSBOM('sbom-1')];
              }
              return null;
            },
          },
        },
      });

      return (
        <QueryClientProvider client={queryClient}>
          <div className="min-h-screen bg-gray-50 dark:bg-gray-950 p-6">
            <Story />
          </div>
        </QueryClientProvider>
      );
    },
  ],
};
