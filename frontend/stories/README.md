# InfraPilot Storybook Stories

This directory contains all Storybook stories for the InfraPilot frontend application.

## Structure

```
stories/
├── components/          # Component-level stories
│   ├── Badge.stories.tsx
│   ├── Card.stories.tsx
│   ├── Table.stories.tsx
│   └── ...
├── pages/              # Full-page stories
│   ├── Dashboard.stories.tsx
│   ├── Deployments.stories.tsx
│   ├── Vulnerabilities.stories.tsx
│   └── README.md
├── mocks/              # Mock data and utilities
│   ├── mockData.ts
│   ├── queryProvider.tsx
│   └── index.ts
└── README.md (this file)
```

## Quick Start

### Run Storybook

```bash
npm run storybook
```

This will start Storybook at `http://localhost:6006`.

### View Stories

Navigate to:
- **Components** - Individual UI components
- **Pages** - Full page implementations

## Page Stories

The following page stories are available:

### 1. Dashboard Page (`pages/Dashboard.stories.tsx`)

Main infrastructure monitoring dashboard.

**Stories:**
- Default - Healthy system state
- Loading - Data fetching state
- Empty State - No agents connected
- With Critical Alerts - Security issues present
- Mixed Container States - Various container statuses
- Minimal Data - Single container/proxy

### 2. Deployments Page (`pages/Deployments.stories.tsx`)

Deployment management with security scanning.

**Stories:**
- Default - Healthy deployments
- With Vulnerabilities - Security issues detected
- Failed Deployment - Failure states
- Loading - Data fetching
- Empty State - No deployments
- No Active Agents - Agent unavailable
- Multiple Environments - Prod/Staging/Dev
- Clean Scan - Zero vulnerabilities

### 3. Vulnerabilities Page (`pages/Vulnerabilities.stories.tsx`)

CVE tracking and vulnerability management.

**Stories:**
- Default - Mixed severities
- Critical Only - High-priority issues
- High Severity Distribution - Mostly high-risk
- Empty State - No vulnerabilities
- Loading - Data fetching
- With Active Deployments - Running vulnerable services
- Policy Enforcement - Blocked deployments
- Large Dataset - 50+ CVEs for performance testing
- Low Severity Only - Maintenance view

## Mock Data System

### Using Mock Data

Import from the mocks directory:

```tsx
import { mockData, createMockQueryDecorator } from '@/stories/mocks';

export const MyStory: Story = {
  decorators: [
    createMockQueryDecorator({
      'agents': mockData.agents(3),
      'deployments': mockData.deployments(10),
    })
  ],
};
```

### Available Mock Factories

#### Single Items
- `mockData.agent()` - Single agent
- `mockData.container()` - Single container
- `mockData.deployment()` - Single deployment
- `mockData.scanResult()` - Single scan result
- `mockData.vulnerability()` - Single vulnerability
- `mockData.alert()` - Single alert
- `mockData.proxy()` - Single proxy

#### Collections
- `mockData.agents(count)` - Multiple agents
- `mockData.containers(count)` - Multiple containers
- `mockData.deployments(count)` - Multiple deployments
- `mockData.vulnerabilities(count, distribution)` - Vulnerabilities with severity distribution
- `mockData.alerts(count, criticalCount)` - Alerts with critical count
- `mockData.proxies(count)` - Multiple proxies

#### Special Variants
- `mockData.scanResults(profile)` - Scan results by severity profile: 'clean', 'low', 'medium', 'high', 'critical'
- `mockData.cveSummaries(distribution)` - CVE summaries with custom severity distribution

### Customizing Mock Data

All mock factories accept an overrides parameter:

```tsx
const customAgent = mockData.agent({
  name: 'My Custom Agent',
  status: 'offline',
  hostname: 'custom-host-01',
});

const criticalDeployment = mockData.deployment({
  status: 'failed',
  policy_decision: 'deny',
  policy_reason: 'Critical vulnerabilities detected',
});
```

## React Query Integration

Page stories use React Query for data fetching. The mock query provider automatically handles queries.

### Basic Pattern

```tsx
export const MyStory: Story = {
  decorators: [
    createMockQueryDecorator({
      // Map query key patterns to mock responses
      'agents': [mockData.agent()],
      'containers': mockData.containers(5),
    })
  ],
};
```

### Query Key Matching

The decorator matches query keys using substring matching:

```tsx
createMockQueryDecorator({
  'agents': mockData.agents(3),
})

// Matches:
// - queryKey: ['agents']
// - queryKey: ['agents', 'agent-1']
// - queryKey: ['agents', 'agent-1', 'containers']
```

### Advanced Usage

For more control, create a custom QueryClient:

```tsx
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';

export const CustomStory: Story = {
  decorators: [
    (Story) => {
      const queryClient = new QueryClient({
        defaultOptions: {
          queries: {
            retry: false,
            staleTime: Infinity,
            queryFn: async ({ queryKey }) => {
              // Custom query function logic
              if (queryKey.includes('special')) {
                return customData;
              }
              return defaultData;
            },
          },
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

## Component Stories

Component stories demonstrate individual UI components in isolation. See the `components/` directory for examples.

Notable component stories:
- **Badge** - Status and severity badges
- **Card** - Card container with variants
- **Table** - Data table with sorting/filtering
- **SlideOver** - Slide-out detail panel
- **FilterPanel** - Filter controls
- **PageHeader** - Page header with breadcrumbs
- **StatCard** - Metric display cards
- **Timeline** - Activity timeline
- **StatusIndicator** - Status badges with pulse

## Creating New Stories

### 1. Component Story

```tsx
import type { Meta, StoryObj } from '@storybook/react';
import { MyComponent } from '@/components/ui/MyComponent';

const meta: Meta<typeof MyComponent> = {
  title: 'Components/MyComponent',
  component: MyComponent,
  parameters: {
    layout: 'centered',
  },
  tags: ['autodocs'],
};

export default meta;
type Story = StoryObj<typeof MyComponent>;

export const Default: Story = {
  args: {
    prop1: 'value1',
    prop2: 'value2',
  },
};

export const Variant: Story = {
  args: {
    ...Default.args,
    variant: 'special',
  },
};
```

### 2. Page Story

```tsx
import type { Meta, StoryObj } from '@storybook/react';
import { mockData, createMockQueryDecorator } from '@/stories/mocks';
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
      'agents': mockData.agents(2),
      'myData': mockData.myCustomData(10),
    })
  ],
};
```

## Best Practices

### Story Organization
- Group related stories together
- Use clear, descriptive story names
- Document what each story demonstrates

### Mock Data
- Use mock data factories for consistency
- Create realistic data scenarios
- Test edge cases (empty, error, loading states)

### Documentation
- Add descriptions to meta and stories
- Use JSDoc comments for complex stories
- Include usage examples

### Accessibility
- Test with a11y addon
- Verify keyboard navigation
- Check color contrast

### Performance
- Test with large datasets
- Verify virtualization works
- Check for memory leaks

## Testing

Stories serve multiple testing purposes:

### Visual Regression Testing
Use Chromatic or Percy to capture screenshots:
```bash
npm run chromatic
```

### Interaction Testing
Test user interactions with Storybook's test runner:
```bash
npm run test-storybook
```

### Accessibility Testing
Built-in a11y addon checks WCAG compliance automatically.

## CI/CD Integration

Stories are built and published in CI:

```bash
# Build Storybook static site
npm run build-storybook

# Run interaction tests
npm run test-storybook -- --ci

# Publish to Chromatic
npm run chromatic -- --project-token=$CHROMATIC_TOKEN
```

## Troubleshooting

### Stories Not Loading
- Check that all imports are correct
- Verify mock data is properly structured
- Check browser console for errors

### Styling Issues
- Ensure `globals.css` is imported in `.storybook/preview.ts`
- Verify Tailwind config is correct
- Check that decorators are applied

### Mock Data Not Working
- Verify query key patterns match
- Check that QueryClient is provided
- Ensure mock functions return correct types

### TypeScript Errors
- Import types from `@/lib/api`
- Check that all required props are provided
- Verify decorator types are correct

## Resources

- [Storybook Documentation](https://storybook.js.org/docs)
- [React Query Docs](https://tanstack.com/query/latest)
- [Tailwind CSS](https://tailwindcss.com/docs)
- [InfraPilot Components](../components/ui/)

## Contributing

When adding new stories:

1. Follow the existing patterns
2. Use mock data factories
3. Add comprehensive documentation
4. Test in multiple states (loading, empty, error)
5. Verify accessibility
6. Update this README if needed
