# Page Stories

This directory contains Storybook stories for full-page components in the InfraPilot application.

## Overview

Page stories demonstrate complete page flows including:
- Data fetching with React Query
- Loading and error states
- Empty states
- Filtering and search functionality
- Interactive behaviors

## Available Stories

### Dashboard (`Dashboard.stories.tsx`)

The main dashboard overview page showing infrastructure health and metrics.

**Stories:**
- **Default**: Healthy system with all components running
- **Loading**: Data loading state
- **EmptyState**: No agents connected
- **WithCriticalAlerts**: System with critical security alerts
- **MixedContainerStates**: Containers in various states
- **MinimalData**: Minimal data scenario

### Deployments (`Deployments.stories.tsx`)

Deployment management and monitoring page with security scanning.

**Stories:**
- **Default**: Healthy deployments across environments
- **WithVulnerabilities**: Deployments with security issues
- **FailedDeployment**: Failed and blocked deployments
- **Loading**: Data loading state
- **EmptyState**: No deployments
- **NoActiveAgents**: No agents available
- **MultipleEnvironments**: Production, staging, and development
- **CleanScan**: Perfect security scan with zero vulnerabilities

### Vulnerabilities (`Vulnerabilities.stories.tsx`)

CVE tracking and management page with filtering capabilities.

**Stories:**
- **Default**: Mixed severity vulnerabilities
- **CriticalOnly**: Only critical severity issues
- **HighSeverityDistribution**: Heavily weighted toward high severity
- **EmptyState**: No vulnerabilities detected
- **Loading**: Data loading state
- **WithActiveDeployments**: Vulnerabilities in running deployments
- **PolicyEnforcement**: Blocked deployments by policy
- **LargeDataset**: Performance testing with 50+ CVEs
- **LowSeverityOnly**: Only low severity issues

## Using the Stories

### Running Storybook

```bash
npm run storybook
```

The Storybook UI will open at `http://localhost:6006`.

### Creating New Stories

1. Create a new `.stories.tsx` file in this directory
2. Import the page component and required dependencies
3. Use the mock data utilities from `@/stories/mocks`
4. Define story variants demonstrating different states

Example:

```tsx
import type { Meta, StoryObj } from '@storybook/react';
import { createMockQueryDecorator, mockData } from '@/stories/mocks';
import MyPage from '@/app/(dashboard)/my-page/page';

const meta: Meta<typeof MyPage> = {
  title: 'Pages/MyPage',
  component: MyPage,
  parameters: {
    layout: 'fullscreen',
  },
};

export default meta;
type Story = StoryObj<typeof MyPage>;

export const Default: Story = {
  decorators: [
    createMockQueryDecorator({
      agents: mockData.agents(2),
      myData: mockData.myCustomData(10),
    })
  ],
};
```

## Mock Data

Mock data factories are available in `@/stories/mocks/mockData.ts`. These provide realistic test data for:

- **Agents**: Infrastructure monitoring agents
- **Containers**: Docker containers
- **Deployments**: Application deployments
- **Scan Results**: Security scan results
- **Vulnerabilities**: CVE vulnerabilities
- **CVE Summaries**: Aggregated vulnerability data
- **Alerts**: System alerts
- **Proxies**: Proxy host configurations
- **SBOMs**: Software Bill of Materials

### Using Mock Data

```tsx
import { mockData } from '@/stories/mocks';

// Create single items
const agent = mockData.agent({ name: 'Custom Agent' });
const deployment = mockData.deployment({ status: 'failed' });

// Create collections
const agents = mockData.agents(5);
const deployments = mockData.deployments(10);

// Create with specific profiles
const cleanScan = mockData.scanResults('clean');
const criticalScan = mockData.scanResults('critical');

// Create vulnerabilities with distribution
const vulns = mockData.vulnerabilities(20, {
  critical: 2,
  high: 5,
  medium: 8,
  low: 5,
});
```

## React Query Integration

Stories use React Query for data fetching. The `createMockQueryDecorator` utility provides a configured QueryClient with mock data.

### Basic Usage

```tsx
export const MyStory: Story = {
  decorators: [
    createMockQueryDecorator({
      '/api/v1/agents': [mockData.agent()],
      '/api/v1/deployments': mockData.deployments(5),
    })
  ],
};
```

### Advanced Usage

```tsx
export const WithDelay: Story = {
  decorators: [
    (Story) => {
      const queryClient = createStoryQueryClient({
        '/api/v1/data': {
          response: mockData.myData(),
          delay: 2000, // 2 second delay
        },
      });

      return (
        <QueryClientProvider client={queryClient}>
          <Story />
        </QueryClientProvider>
      );
    },
  ],
};
```

## Best Practices

1. **Comprehensive Coverage**: Create stories for all major states (loading, empty, error, success)
2. **Realistic Data**: Use mock data factories to ensure consistency
3. **Clear Documentation**: Add descriptions explaining what each story demonstrates
4. **Interactive**: Make stories interactive where appropriate
5. **Accessibility**: Test stories with accessibility tools (a11y addon)

## Testing with Stories

Stories can be used for:

- **Visual regression testing**: Capture screenshots of each story
- **Interaction testing**: Test user interactions with Storybook's test runner
- **Accessibility testing**: Verify WCAG compliance
- **Documentation**: Serve as living documentation for the team

## Troubleshooting

### Mock Data Not Loading

Ensure your query key patterns match the mock data map keys:

```tsx
// This will match queries containing 'agents'
createMockQueryDecorator({
  'agents': mockData.agents(3),
})

// Query key: ['agents'] ✅ Matches
// Query key: ['agents', 'agent-1'] ✅ Matches
// Query key: ['users'] ❌ Doesn't match
```

### TypeScript Errors

Make sure to import types from `@/lib/api`:

```tsx
import type { Agent, Deployment } from '@/lib/api';
```

### Styling Issues

Stories include the full app layout by default. If styling looks incorrect:

1. Check that `globals.css` is imported in `.storybook/preview.ts`
2. Verify Tailwind config is correct
3. Ensure dark mode classes are applied if needed

## Resources

- [Storybook Documentation](https://storybook.js.org/docs)
- [React Query Documentation](https://tanstack.com/query/latest/docs/react/overview)
- [Component Stories](../components/) - See component-level stories for reference
