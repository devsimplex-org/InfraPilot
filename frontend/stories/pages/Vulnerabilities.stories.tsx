import type { Meta, StoryObj } from '@storybook/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import VulnerabilitiesPage from '@/app/(dashboard)/vulnerabilities/page';

/**
 * Vulnerabilities Page
 *
 * The vulnerabilities page provides a comprehensive view of all CVE (Common Vulnerabilities
 * and Exposures) across deployments. It enables security teams to track, prioritize, and
 * remediate vulnerabilities efficiently.
 *
 * Features:
 * - CVE listing with severity filtering
 * - Search by CVE ID, description, or affected package
 * - Package filtering to focus on specific dependencies
 * - Detailed CVE information including CVSS scores
 * - Running vs. blocked deployment tracking
 * - Affected package versions and fix availability
 * - Policy enforcement visualization
 */
const meta: Meta<typeof VulnerabilitiesPage> = {
  title: 'Pages/Vulnerabilities',
  component: VulnerabilitiesPage,
  parameters: {
    layout: 'fullscreen',
    docs: {
      description: {
        component: 'The vulnerabilities page tracks and manages CVEs across all deployments with filtering and detailed information.',
      },
    },
  },
};

export default meta;
type Story = StoryObj<typeof VulnerabilitiesPage>;

/**
 * Mock Data Types
 */
interface CVESummary {
  cve_id: string;
  severity: string;
  cvss_v3_score: number | null;
  description: string;
  affected_packages: string[];
  running_count: number;
  blocked_count: number;
  first_seen: string;
  last_seen: string;
}

interface CVEDetail {
  cve_id: string;
  severity: string;
  cvss_v3_score: number | null;
  description: string;
  published_date: string | null;
  last_modified_date: string | null;
  references: string[];
  affected_packages: Array<{
    package_name: string;
    package_version: string;
    fixed_version: string;
  }>;
  running_deployments: Array<{
    deployment_id: string;
    service_name: string;
    environment: string;
    image_repository: string;
    image_tag: string;
    status: string;
    created_at: string;
    package_name: string;
    package_version: string;
    policy_blocked: boolean;
    policy_reason: string | null;
  }>;
  blocked_deployments: Array<{
    deployment_id: string;
    service_name: string;
    environment: string;
    image_repository: string;
    image_tag: string;
    status: string;
    created_at: string;
    package_name: string;
    package_version: string;
    policy_blocked: boolean;
    policy_reason: string | null;
  }>;
  first_detected: string;
  last_detected: string;
  total_occurrences: number;
}

/**
 * Mock Data Helpers
 */
const createMockAgent = () => ({
  id: 'agent-1',
  org_id: 'org-1',
  name: 'Production Agent',
  hostname: 'prod-server-01',
  status: 'active' as const,
  version: '1.0.0',
  last_seen_at: new Date().toISOString(),
  created_at: new Date(Date.now() - 86400000 * 30).toISOString(),
});

const createMockCVE = (
  id: number,
  severity: 'critical' | 'high' | 'medium' | 'low',
  runningCount: number = 0,
  blockedCount: number = 0
): CVESummary => {
  const packages = [
    'openssl', 'libcurl', 'zlib', 'openssl-libs', 'systemd', 'glibc',
    'python3', 'nginx', 'nodejs', 'redis', 'postgres', 'mongodb'
  ];

  const descriptions = {
    critical: [
      'Remote code execution vulnerability allowing arbitrary command execution',
      'Critical buffer overflow leading to potential system compromise',
      'Authentication bypass vulnerability enabling unauthorized access',
    ],
    high: [
      'Privilege escalation vulnerability in authentication mechanism',
      'SQL injection vulnerability in query processing',
      'Cross-site scripting (XSS) vulnerability in user input handling',
    ],
    medium: [
      'Information disclosure vulnerability exposing sensitive data',
      'Denial of service vulnerability causing service unavailability',
      'Path traversal vulnerability allowing unauthorized file access',
    ],
    low: [
      'Minor information leak in error messages',
      'Weak default configuration allowing potential security issues',
      'Race condition in concurrent operations',
    ],
  };

  const cvssScores = {
    critical: 9.0 + Math.random() * 1.0,
    high: 7.0 + Math.random() * 2.0,
    medium: 4.0 + Math.random() * 3.0,
    low: 1.0 + Math.random() * 3.0,
  };

  return {
    cve_id: `CVE-2024-${10000 + id}`,
    severity,
    cvss_v3_score: parseFloat(cvssScores[severity].toFixed(1)),
    description: descriptions[severity][id % descriptions[severity].length],
    affected_packages: packages.slice(id % 3, (id % 3) + 2),
    running_count: runningCount,
    blocked_count: blockedCount,
    first_seen: new Date(Date.now() - 86400000 * (30 - id)).toISOString(),
    last_seen: new Date(Date.now() - 86400000 * (id % 7)).toISOString(),
  };
};

const createMockCVEDetail = (cve: CVESummary): CVEDetail => {
  const hasRunningDeployments = cve.running_count > 0;
  const hasBlockedDeployments = cve.blocked_count > 0;

  return {
    cve_id: cve.cve_id,
    severity: cve.severity,
    cvss_v3_score: cve.cvss_v3_score,
    description: cve.description,
    published_date: new Date(Date.now() - 86400000 * 45).toISOString(),
    last_modified_date: new Date(Date.now() - 86400000 * 15).toISOString(),
    references: [
      'https://nvd.nist.gov/vuln/detail/' + cve.cve_id,
      'https://cve.mitre.org/cgi-bin/cvename.cgi?name=' + cve.cve_id,
    ],
    affected_packages: cve.affected_packages.map((pkg) => ({
      package_name: pkg,
      package_version: '1.0.0',
      fixed_version: cve.severity !== 'low' ? '1.1.0' : '',
    })),
    running_deployments: hasRunningDeployments
      ? Array.from({ length: cve.running_count }, (_, i) => ({
          deployment_id: `deploy-${i}`,
          service_name: `production-service-${i + 1}`,
          environment: 'production',
          image_repository: 'myorg/service',
          image_tag: `v1.${i}.0`,
          status: 'running',
          created_at: new Date(Date.now() - 86400000 * (i + 1)).toISOString(),
          package_name: cve.affected_packages[0],
          package_version: '1.0.0',
          policy_blocked: false,
          policy_reason: null,
        }))
      : [],
    blocked_deployments: hasBlockedDeployments
      ? Array.from({ length: cve.blocked_count }, (_, i) => ({
          deployment_id: `blocked-${i}`,
          service_name: `blocked-service-${i + 1}`,
          environment: 'production',
          image_repository: 'myorg/service',
          image_tag: `v2.${i}.0`,
          status: 'blocked',
          created_at: new Date(Date.now() - 86400000 * (i + 5)).toISOString(),
          package_name: cve.affected_packages[0],
          package_version: '1.0.0',
          policy_blocked: true,
          policy_reason: `Blocked due to ${cve.severity} severity vulnerability: ${cve.cve_id}`,
        }))
      : [],
    first_detected: cve.first_seen,
    last_detected: cve.last_seen,
    total_occurrences: cve.running_count + cve.blocked_count,
  };
};

/**
 * Default State - Mixed Vulnerabilities
 *
 * Shows a typical vulnerability landscape with:
 * - Mix of all severity levels
 * - Some running deployments affected
 * - Some deployments blocked by policy
 */
export const Default: Story = {
  decorators: [
    (Story) => {
      const cves = [
        createMockCVE(1, 'critical', 3, 2),
        createMockCVE(2, 'critical', 1, 5),
        createMockCVE(3, 'high', 5, 0),
        createMockCVE(4, 'high', 2, 3),
        createMockCVE(5, 'high', 4, 1),
        createMockCVE(6, 'medium', 8, 0),
        createMockCVE(7, 'medium', 3, 0),
        createMockCVE(8, 'medium', 6, 0),
        createMockCVE(9, 'low', 12, 0),
        createMockCVE(10, 'low', 7, 0),
      ];

      const queryClient = new QueryClient({
        defaultOptions: {
          queries: {
            retry: false,
            staleTime: Infinity,
            queryFn: async ({ queryKey }) => {
              const key = JSON.stringify(queryKey);

              if (key.includes('agents')) {
                return [createMockAgent()];
              }
              if (key.includes('cve-detail')) {
                // Extract CVE ID from query key
                const cveId = queryKey[2] as string;
                const cve = cves.find((c) => c.cve_id === cveId);
                return cve ? createMockCVEDetail(cve) : null;
              }
              if (key.includes('cves')) {
                return { cves, count: cves.length };
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
 * Critical Only - High Priority Issues
 *
 * Filtered view showing only critical vulnerabilities.
 * Useful for security teams to focus on the most urgent issues.
 */
export const CriticalOnly: Story = {
  decorators: [
    (Story) => {
      const cves = [
        createMockCVE(1, 'critical', 5, 3),
        createMockCVE(2, 'critical', 2, 8),
        createMockCVE(3, 'critical', 4, 6),
        createMockCVE(11, 'critical', 1, 2),
      ];

      const queryClient = new QueryClient({
        defaultOptions: {
          queries: {
            retry: false,
            staleTime: Infinity,
            queryFn: async ({ queryKey }) => {
              const key = JSON.stringify(queryKey);

              if (key.includes('agents')) {
                return [createMockAgent()];
              }
              if (key.includes('cve-detail')) {
                const cveId = queryKey[2] as string;
                const cve = cves.find((c) => c.cve_id === cveId);
                return cve ? createMockCVEDetail(cve) : null;
              }
              if (key.includes('cves')) {
                return { cves, count: cves.length };
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
 * High Severity Distribution
 *
 * Shows a distribution heavily weighted toward high severity issues.
 * Demonstrates the vulnerability overview with mostly high-risk items.
 */
export const HighSeverityDistribution: Story = {
  decorators: [
    (Story) => {
      const cves = [
        createMockCVE(1, 'critical', 2, 1),
        ...Array.from({ length: 8 }, (_, i) => createMockCVE(i + 2, 'high', 3, 1)),
        createMockCVE(11, 'medium', 5, 0),
        createMockCVE(12, 'low', 8, 0),
      ];

      const queryClient = new QueryClient({
        defaultOptions: {
          queries: {
            retry: false,
            staleTime: Infinity,
            queryFn: async ({ queryKey }) => {
              const key = JSON.stringify(queryKey);

              if (key.includes('agents')) {
                return [createMockAgent()];
              }
              if (key.includes('cve-detail')) {
                const cveId = queryKey[2] as string;
                const cve = cves.find((c) => c.cve_id === cveId);
                return cve ? createMockCVEDetail(cve) : null;
              }
              if (key.includes('cves')) {
                return { cves, count: cves.length };
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
 * Empty State - No Vulnerabilities
 *
 * The ideal state - no vulnerabilities detected.
 * Shows when all images are clean after security scanning.
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

              if (key.includes('agents')) {
                return [createMockAgent()];
              }
              if (key.includes('cves')) {
                return { cves: [], count: 0 };
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
 * Shows the page while vulnerability data is being fetched.
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

              if (key.includes('agents')) {
                return [createMockAgent()];
              }
              // Return pending promise for CVEs
              return new Promise(() => {});
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
 * With Active Deployments - Security Risk
 *
 * Shows vulnerabilities that are actively running in production.
 * Highlights the urgency with high running deployment counts.
 */
export const WithActiveDeployments: Story = {
  decorators: [
    (Story) => {
      const cves = [
        createMockCVE(1, 'critical', 15, 0),
        createMockCVE(2, 'critical', 8, 0),
        createMockCVE(3, 'high', 22, 0),
        createMockCVE(4, 'high', 12, 0),
        createMockCVE(5, 'medium', 35, 0),
        createMockCVE(6, 'low', 48, 0),
      ];

      const queryClient = new QueryClient({
        defaultOptions: {
          queries: {
            retry: false,
            staleTime: Infinity,
            queryFn: async ({ queryKey }) => {
              const key = JSON.stringify(queryKey);

              if (key.includes('agents')) {
                return [createMockAgent()];
              }
              if (key.includes('cve-detail')) {
                const cveId = queryKey[2] as string;
                const cve = cves.find((c) => c.cve_id === cveId);
                return cve ? createMockCVEDetail(cve) : null;
              }
              if (key.includes('cves')) {
                return { cves, count: cves.length };
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
 * Policy Enforcement - Blocked Deployments
 *
 * Shows the effectiveness of security policies.
 * Most vulnerabilities are caught and deployments blocked.
 */
export const PolicyEnforcement: Story = {
  decorators: [
    (Story) => {
      const cves = [
        createMockCVE(1, 'critical', 0, 12),
        createMockCVE(2, 'critical', 1, 8),
        createMockCVE(3, 'high', 2, 15),
        createMockCVE(4, 'high', 0, 9),
        createMockCVE(5, 'medium', 5, 6),
        createMockCVE(6, 'medium', 3, 4),
      ];

      const queryClient = new QueryClient({
        defaultOptions: {
          queries: {
            retry: false,
            staleTime: Infinity,
            queryFn: async ({ queryKey }) => {
              const key = JSON.stringify(queryKey);

              if (key.includes('agents')) {
                return [createMockAgent()];
              }
              if (key.includes('cve-detail')) {
                const cveId = queryKey[2] as string;
                const cve = cves.find((c) => c.cve_id === cveId);
                return cve ? createMockCVEDetail(cve) : null;
              }
              if (key.includes('cves')) {
                return { cves, count: cves.length };
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
 * Large Dataset - Performance Test
 *
 * Tests the page with a large number of vulnerabilities.
 * Useful for testing table performance and filtering.
 */
export const LargeDataset: Story = {
  decorators: [
    (Story) => {
      const severities: Array<'critical' | 'high' | 'medium' | 'low'> = ['critical', 'high', 'medium', 'low'];
      const cves = Array.from({ length: 50 }, (_, i) =>
        createMockCVE(
          i,
          severities[i % severities.length],
          Math.floor(Math.random() * 10),
          Math.floor(Math.random() * 5)
        )
      );

      const queryClient = new QueryClient({
        defaultOptions: {
          queries: {
            retry: false,
            staleTime: Infinity,
            queryFn: async ({ queryKey }) => {
              const key = JSON.stringify(queryKey);

              if (key.includes('agents')) {
                return [createMockAgent()];
              }
              if (key.includes('cve-detail')) {
                const cveId = queryKey[2] as string;
                const cve = cves.find((c) => c.cve_id === cveId);
                return cve ? createMockCVEDetail(cve) : null;
              }
              if (key.includes('cves')) {
                return { cves, count: cves.length };
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
 * Low Severity Only - Maintenance View
 *
 * Shows only low severity issues for routine maintenance.
 * These typically don't require immediate action.
 */
export const LowSeverityOnly: Story = {
  decorators: [
    (Story) => {
      const cves = Array.from({ length: 15 }, (_, i) =>
        createMockCVE(i, 'low', Math.floor(Math.random() * 20) + 5, 0)
      );

      const queryClient = new QueryClient({
        defaultOptions: {
          queries: {
            retry: false,
            staleTime: Infinity,
            queryFn: async ({ queryKey }) => {
              const key = JSON.stringify(queryKey);

              if (key.includes('agents')) {
                return [createMockAgent()];
              }
              if (key.includes('cve-detail')) {
                const cveId = queryKey[2] as string;
                const cve = cves.find((c) => c.cve_id === cveId);
                return cve ? createMockCVEDetail(cve) : null;
              }
              if (key.includes('cves')) {
                return { cves, count: cves.length };
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
