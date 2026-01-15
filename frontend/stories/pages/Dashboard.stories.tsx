import type { Meta, StoryObj } from '@storybook/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import DashboardPage from '@/app/(dashboard)/dashboard-refactored/page';

/**
 * Dashboard Page
 *
 * The main dashboard provides an overview of infrastructure security and operations.
 * It displays key metrics, system status, recent activity, and quick access to containers and proxies.
 *
 * Features:
 * - Real-time metrics for deployments, alerts, security posture, and infrastructure
 * - System health status indicators
 * - Recent activity timeline
 * - Container and proxy host summaries
 */
const meta: Meta<typeof DashboardPage> = {
  title: 'Pages/Dashboard',
  component: DashboardPage,
  parameters: {
    layout: 'fullscreen',
    docs: {
      description: {
        component: 'The dashboard page shows a comprehensive overview of the infrastructure monitoring system.',
      },
    },
  },
  decorators: [
    (Story) => {
      const queryClient = new QueryClient({
        defaultOptions: {
          queries: {
            retry: false,
            staleTime: Infinity,
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

export default meta;
type Story = StoryObj<typeof DashboardPage>;

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

const createMockContainers = (count: number) => {
  const statuses = ['running', 'exited', 'paused'];
  return Array.from({ length: count }, (_, i) => ({
    id: `container-${i}`,
    agent_id: 'agent-1',
    container_id: `abc${i}def${i}123${i}`,
    name: i === 0 ? 'production-api-v2' : i === 1 ? 'redis-cache' : i === 2 ? 'postgres-db' : `service-${i}`,
    image: i === 0 ? 'myapp/api:v2.3.1' : i === 1 ? 'redis:7-alpine' : i === 2 ? 'postgres:15' : `service-${i}:latest`,
    stack_name: i < 3 ? 'production' : null,
    status: i < count - 2 ? 'running' : statuses[i % statuses.length],
    state: 'running',
    cpu_percent: Math.random() * 80,
    memory_mb: Math.floor(Math.random() * 2048) + 256,
    memory_limit_mb: 4096,
    restart_count: Math.floor(Math.random() * 3),
    networks: ['bridge', 'internal'],
    created_at: new Date(Date.now() - 86400000 * (i + 1)).toISOString(),
  }));
};

const createMockProxies = (count: number) => {
  return Array.from({ length: count }, (_, i) => ({
    id: `proxy-${i}`,
    domain: i === 0 ? 'api.example.com' : i === 1 ? 'app.example.com' : `service-${i}.example.com`,
    upstream_target: i === 0 ? 'http://api:3000' : i === 1 ? 'http://app:8080' : `http://service-${i}:8000`,
    status: i === count - 1 ? 'inactive' : 'active',
    ssl_enabled: i < 2,
    created_at: new Date(Date.now() - 86400000 * (i + 1)).toISOString(),
  }));
};

const createMockAlerts = (count: number, criticalCount: number = 0) => {
  const severities = ['critical', 'high', 'medium', 'low'];
  return Array.from({ length: count }, (_, i) => ({
    id: `alert-${i}`,
    message: i === 0 && criticalCount > 0
      ? 'Critical vulnerability detected in production-api-v2 (CVE-2024-12345)'
      : i === 1
      ? 'High CPU usage detected on container redis-cache'
      : i === 2
      ? 'New image scan completed for postgres-db'
      : `System alert ${i}`,
    severity: i < criticalCount ? 'critical' : severities[Math.min(i, severities.length - 1)],
    triggered_at: new Date(Date.now() - 1000 * 60 * (i * 15 + 5)).toISOString(),
    resolved_at: i >= count - 2 ? new Date(Date.now() - 1000 * 60 * (i * 10)).toISOString() : null,
  }));
};

/**
 * Default State - Healthy System
 *
 * Demonstrates the dashboard in an ideal state with:
 * - All containers running
 * - Active agents online
 * - No critical alerts
 * - Recent resolved activity
 */
export const Default: Story = {
  parameters: {
    mockData: [
      {
        url: '/api/v1/agents',
        method: 'GET',
        status: 200,
        response: [
          createMockAgent(),
          createMockAgent({ id: 'agent-2', name: 'Staging Agent', status: 'active' }),
        ],
      },
      {
        url: '/api/v1/agents/agent-1/containers',
        method: 'GET',
        status: 200,
        response: createMockContainers(8),
      },
      {
        url: '/api/v1/agents/agent-1/proxies',
        method: 'GET',
        status: 200,
        response: createMockProxies(5),
      },
      {
        url: '/api/v1/alerts/history?limit=10',
        method: 'GET',
        status: 200,
        response: createMockAlerts(5, 0),
      },
    ],
  },
  decorators: [
    (Story, context) => {
      const queryClient = new QueryClient({
        defaultOptions: {
          queries: {
            retry: false,
            staleTime: Infinity,
            queryFn: async ({ queryKey }) => {
              const mockData = context.parameters.mockData || [];
              const key = JSON.stringify(queryKey);

              if (key.includes('agents') && !key.includes('containers') && !key.includes('proxies')) {
                const mock = mockData.find((m: any) => m.url === '/api/v1/agents');
                return mock?.response || [];
              }
              if (key.includes('containers')) {
                const mock = mockData.find((m: any) => m.url.includes('containers'));
                return mock?.response || [];
              }
              if (key.includes('proxies')) {
                const mock = mockData.find((m: any) => m.url.includes('proxies'));
                return mock?.response || [];
              }
              if (key.includes('alertHistory')) {
                const mock = mockData.find((m: any) => m.url.includes('alerts'));
                return mock?.response || [];
              }
              return [];
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
 * Shows the dashboard while data is being fetched.
 * Displays a loading spinner with appropriate message.
 */
export const Loading: Story = {
  decorators: [
    (Story) => {
      const queryClient = new QueryClient({
        defaultOptions: {
          queries: {
            retry: false,
            staleTime: Infinity,
            queryFn: async () => {
              // Return a pending promise that never resolves
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
 * Empty State - No Active Agents
 *
 * Shows the state when no agents are connected to the system.
 * Displays an empty state with a call-to-action to connect an agent.
 */
export const EmptyState: Story = {
  parameters: {
    mockData: [
      {
        url: '/api/v1/agents',
        method: 'GET',
        status: 200,
        response: [],
      },
    ],
  },
  decorators: [
    (Story, context) => {
      const queryClient = new QueryClient({
        defaultOptions: {
          queries: {
            retry: false,
            staleTime: Infinity,
            queryFn: async () => {
              return context.parameters.mockData[0].response;
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
 * Critical Alerts State
 *
 * Demonstrates the dashboard when there are critical security alerts.
 * Shows:
 * - Critical vulnerabilities detected
 * - Red status indicators
 * - Urgent alerts in the activity timeline
 * - Degraded security posture
 */
export const WithCriticalAlerts: Story = {
  parameters: {
    mockData: [
      {
        url: '/api/v1/agents',
        method: 'GET',
        status: 200,
        response: [createMockAgent()],
      },
      {
        url: '/api/v1/agents/agent-1/containers',
        method: 'GET',
        status: 200,
        response: createMockContainers(6),
      },
      {
        url: '/api/v1/agents/agent-1/proxies',
        method: 'GET',
        status: 200,
        response: createMockProxies(3),
      },
      {
        url: '/api/v1/alerts/history?limit=10',
        method: 'GET',
        status: 200,
        response: createMockAlerts(8, 3),
      },
    ],
  },
  decorators: [
    (Story, context) => {
      const queryClient = new QueryClient({
        defaultOptions: {
          queries: {
            retry: false,
            staleTime: Infinity,
            queryFn: async ({ queryKey }) => {
              const mockData = context.parameters.mockData || [];
              const key = JSON.stringify(queryKey);

              if (key.includes('agents') && !key.includes('containers') && !key.includes('proxies')) {
                const mock = mockData.find((m: any) => m.url === '/api/v1/agents');
                return mock?.response || [];
              }
              if (key.includes('containers')) {
                const mock = mockData.find((m: any) => m.url.includes('containers'));
                return mock?.response || [];
              }
              if (key.includes('proxies')) {
                const mock = mockData.find((m: any) => m.url.includes('proxies'));
                return mock?.response || [];
              }
              if (key.includes('alertHistory')) {
                const mock = mockData.find((m: any) => m.url.includes('alerts'));
                return mock?.response || [];
              }
              return [];
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
 * Mixed Container States
 *
 * Shows the dashboard with containers in various states.
 * Some containers running, some stopped, demonstrating:
 * - Partial system health
 * - Warning indicators
 * - Mixed status displays
 */
export const MixedContainerStates: Story = {
  parameters: {
    mockData: [
      {
        url: '/api/v1/agents',
        method: 'GET',
        status: 200,
        response: [
          createMockAgent(),
          createMockAgent({ id: 'agent-2', name: 'Staging Agent', status: 'offline' }),
        ],
      },
      {
        url: '/api/v1/agents/agent-1/containers',
        method: 'GET',
        status: 200,
        response: [
          ...createMockContainers(4),
          {
            id: 'container-stopped-1',
            agent_id: 'agent-1',
            container_id: 'stopped123',
            name: 'maintenance-service',
            image: 'service:v1.0.0',
            stack_name: null,
            status: 'exited',
            state: 'exited',
            cpu_percent: 0,
            memory_mb: 0,
            memory_limit_mb: 2048,
            restart_count: 5,
            networks: ['bridge'],
            created_at: new Date(Date.now() - 86400000 * 2).toISOString(),
          },
        ],
      },
      {
        url: '/api/v1/agents/agent-1/proxies',
        method: 'GET',
        status: 200,
        response: createMockProxies(4),
      },
      {
        url: '/api/v1/alerts/history?limit=10',
        method: 'GET',
        status: 200,
        response: createMockAlerts(6, 1),
      },
    ],
  },
  decorators: [
    (Story, context) => {
      const queryClient = new QueryClient({
        defaultOptions: {
          queries: {
            retry: false,
            staleTime: Infinity,
            queryFn: async ({ queryKey }) => {
              const mockData = context.parameters.mockData || [];
              const key = JSON.stringify(queryKey);

              if (key.includes('agents') && !key.includes('containers') && !key.includes('proxies')) {
                const mock = mockData.find((m: any) => m.url === '/api/v1/agents');
                return mock?.response || [];
              }
              if (key.includes('containers')) {
                const mock = mockData.find((m: any) => m.url.includes('containers'));
                return mock?.response || [];
              }
              if (key.includes('proxies')) {
                const mock = mockData.find((m: any) => m.url.includes('proxies'));
                return mock?.response || [];
              }
              if (key.includes('alertHistory')) {
                const mock = mockData.find((m: any) => m.url.includes('alerts'));
                return mock?.response || [];
              }
              return [];
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
 * Minimal Data
 *
 * Dashboard with minimal data - just one container and proxy.
 * Useful for testing empty states within populated dashboard.
 */
export const MinimalData: Story = {
  parameters: {
    mockData: [
      {
        url: '/api/v1/agents',
        method: 'GET',
        status: 200,
        response: [createMockAgent()],
      },
      {
        url: '/api/v1/agents/agent-1/containers',
        method: 'GET',
        status: 200,
        response: createMockContainers(1),
      },
      {
        url: '/api/v1/agents/agent-1/proxies',
        method: 'GET',
        status: 200,
        response: createMockProxies(1),
      },
      {
        url: '/api/v1/alerts/history?limit=10',
        method: 'GET',
        status: 200,
        response: [],
      },
    ],
  },
  decorators: [
    (Story, context) => {
      const queryClient = new QueryClient({
        defaultOptions: {
          queries: {
            retry: false,
            staleTime: Infinity,
            queryFn: async ({ queryKey }) => {
              const mockData = context.parameters.mockData || [];
              const key = JSON.stringify(queryKey);

              if (key.includes('agents') && !key.includes('containers') && !key.includes('proxies')) {
                const mock = mockData.find((m: any) => m.url === '/api/v1/agents');
                return mock?.response || [];
              }
              if (key.includes('containers')) {
                const mock = mockData.find((m: any) => m.url.includes('containers'));
                return mock?.response || [];
              }
              if (key.includes('proxies')) {
                const mock = mockData.find((m: any) => m.url.includes('proxies'));
                return mock?.response || [];
              }
              if (key.includes('alertHistory')) {
                const mock = mockData.find((m: any) => m.url.includes('alerts'));
                return mock?.response || [];
              }
              return [];
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
