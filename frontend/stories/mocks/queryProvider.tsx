import { ReactNode } from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';

/**
 * Mock Query Provider for Storybook
 *
 * This utility creates a React Query provider configured for Storybook stories.
 * It disables retries and sets infinite stale time to ensure predictable behavior.
 *
 * Usage:
 * ```tsx
 * export const MyStory: Story = {
 *   decorators: [
 *     createMockQueryDecorator({
 *       '/api/v1/agents': { response: [mockAgent], status: 200 },
 *       '/api/v1/deployments': { response: [mockDeployment], status: 200 },
 *     })
 *   ]
 * };
 * ```
 */

export interface MockResponse {
  response: any;
  status?: number;
  delay?: number;
}

export type MockDataMap = Record<string, MockResponse>;

/**
 * Creates a QueryClient configured for Storybook
 */
export function createStoryQueryClient(mockData: MockDataMap = {}) {
  return new QueryClient({
    defaultOptions: {
      queries: {
        retry: false,
        staleTime: Infinity,
        queryFn: async ({ queryKey }) => {
          const key = JSON.stringify(queryKey);

          // Find matching mock based on query key patterns
          for (const [pattern, mock] of Object.entries(mockData)) {
            if (key.includes(pattern)) {
              // Simulate network delay if specified
              if (mock.delay) {
                await new Promise((resolve) => setTimeout(resolve, mock.delay));
              }

              // Simulate error responses
              if (mock.status && mock.status >= 400) {
                throw new Error(`Mock API error: ${mock.status}`);
              }

              return mock.response;
            }
          }

          // Default response for unmatched queries
          return null;
        },
      },
    },
  });
}

/**
 * Creates a decorator for Storybook that provides React Query context with mock data
 */
export function createMockQueryDecorator(mockData: MockDataMap = {}) {
  return (Story: () => ReactNode) => {
    const queryClient = createStoryQueryClient(mockData);

    return (
      <QueryClientProvider client={queryClient}>
        <div className="min-h-screen bg-gray-50 dark:bg-gray-950 p-6">
          <Story />
        </div>
      </QueryClientProvider>
    );
  };
}

/**
 * Simple wrapper for stories that need QueryClient but no mock data
 */
export function MockQueryProvider({ children }: { children: ReactNode }) {
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
      {children}
    </QueryClientProvider>
  );
}
