# Storybook Quick Reference

## 🚀 Getting Started

```bash
# Start Storybook
npm run storybook

# Build Storybook
npm run build-storybook
```

## 📚 Available Page Stories

### Dashboard (`Pages/Dashboard`)
```
✓ Default - Healthy system
✓ Loading - Data fetching
✓ Empty State - No agents
✓ With Critical Alerts - Security issues
✓ Mixed Container States - Various statuses
✓ Minimal Data - Single items
```

### Deployments (`Pages/Deployments`)
```
✓ Default - Healthy deployments
✓ With Vulnerabilities - Security issues
✓ Failed Deployment - Failure states
✓ Loading - Data fetching
✓ Empty State - No deployments
✓ No Active Agents - Agent unavailable
✓ Multiple Environments - Prod/Staging/Dev
✓ Clean Scan - Zero vulnerabilities
```

### Vulnerabilities (`Pages/Vulnerabilities`)
```
✓ Default - Mixed severities
✓ Critical Only - High priority
✓ High Severity Distribution - Mostly high-risk
✓ Empty State - No vulnerabilities
✓ Loading - Data fetching
✓ With Active Deployments - Running vulnerable services
✓ Policy Enforcement - Blocked deployments
✓ Large Dataset - 50+ CVEs
✓ Low Severity Only - Maintenance view
```

## 🎭 Creating Stories

### Component Story Template

```tsx
import type { Meta, StoryObj } from '@storybook/react';
import { MyComponent } from '@/components/ui/MyComponent';

const meta: Meta<typeof MyComponent> = {
  title: 'Components/MyComponent',
  component: MyComponent,
  tags: ['autodocs'],
};

export default meta;
type Story = StoryObj<typeof MyComponent>;

export const Default: Story = {
  args: {
    prop: 'value',
  },
};
```

### Page Story Template

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
      'agents': mockData.agents(3),
      'myData': mockData.myCustomData(10),
    })
  ],
};
```

## 🎲 Mock Data Cheat Sheet

### Single Items
```tsx
mockData.agent()           // Single agent
mockData.container()       // Single container
mockData.deployment()      // Single deployment
mockData.scanResult()      // Single scan
mockData.vulnerability()   // Single vulnerability
mockData.alert()           // Single alert
mockData.proxy()           // Single proxy
```

### Collections
```tsx
mockData.agents(5)                    // 5 agents
mockData.containers(8)                // 8 containers
mockData.deployments(10)              // 10 deployments
mockData.vulnerabilities(20, {        // 20 vulnerabilities
  critical: 2,
  high: 5,
  medium: 8,
  low: 5,
})
mockData.alerts(10, 3)                // 10 alerts, 3 critical
mockData.proxies(5)                   // 5 proxies
```

### Special Variants
```tsx
// Scan result profiles
mockData.scanResults('clean')        // 0 vulnerabilities
mockData.scanResults('low')          // Low severity only
mockData.scanResults('medium')       // Mixed vulnerabilities
mockData.scanResults('high')         // Many high severity
mockData.scanResults('critical')     // Critical vulnerabilities

// CVE summaries
mockData.cveSummaries({
  critical: 5,
  high: 10,
  medium: 15,
  low: 20,
})
```

### Customization
```tsx
// Override any field
const customAgent = mockData.agent({
  name: 'Custom Agent',
  status: 'offline',
  hostname: 'my-host',
});

const failedDeployment = mockData.deployment({
  status: 'failed',
  policy_decision: 'deny',
  policy_reason: 'Critical vulnerabilities',
});
```

## 🔌 React Query Integration

### Basic Usage
```tsx
import { createMockQueryDecorator } from '@/stories/mocks';

export const MyStory: Story = {
  decorators: [
    createMockQueryDecorator({
      'agents': mockData.agents(3),
      'deployments': mockData.deployments(5),
    })
  ],
};
```

### Query Key Patterns
```tsx
// Matches any query containing 'agents'
'agents': mockData.agents(3)

// Matches:
// - ['agents']
// - ['agents', 'agent-1']
// - ['agents', 'agent-1', 'containers']
```

### Advanced Pattern
```tsx
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';

export const Custom: Story = {
  decorators: [
    (Story) => {
      const queryClient = new QueryClient({
        defaultOptions: {
          queries: {
            retry: false,
            staleTime: Infinity,
            queryFn: async ({ queryKey }) => {
              // Custom logic
              return customData;
            },
          },
        },
      });

      return (
        <QueryClientProvider client={queryClient}>
          <div className="min-h-screen bg-gray-50 p-6">
            <Story />
          </div>
        </QueryClientProvider>
      );
    },
  ],
};
```

## 📖 Common Patterns

### Loading State
```tsx
export const Loading: Story = {
  decorators: [
    (Story) => {
      const queryClient = new QueryClient({
        defaultOptions: {
          queries: {
            queryFn: async () => new Promise(() => {}), // Never resolves
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

### Empty State
```tsx
export const Empty: Story = {
  decorators: [
    createMockQueryDecorator({
      'agents': [],
      'deployments': [],
    })
  ],
};
```

### Error State
```tsx
export const Error: Story = {
  decorators: [
    createMockQueryDecorator({
      'data': { response: null, status: 500 }
    })
  ],
};
```

### Large Dataset
```tsx
export const LargeData: Story = {
  decorators: [
    createMockQueryDecorator({
      'items': Array.from({ length: 100 }, (_, i) =>
        mockData.item({ id: `item-${i}` })
      ),
    })
  ],
};
```

## 🎨 Story Parameters

### Layout
```tsx
parameters: {
  layout: 'centered',    // Center in viewport
  layout: 'fullscreen',  // Full screen
  layout: 'padded',      // Default with padding
}
```

### Backgrounds
```tsx
parameters: {
  backgrounds: {
    default: 'dark',
    values: [
      { name: 'light', value: '#ffffff' },
      { name: 'dark', value: '#000000' },
    ],
  },
}
```

### Viewport
```tsx
parameters: {
  viewport: {
    defaultViewport: 'mobile1',  // Mobile view
    defaultViewport: 'tablet',   // Tablet view
  },
}
```

## 🧪 Testing

### Visual Regression
```bash
npm run chromatic
```

### Interaction Testing
```bash
npm run test-storybook
```

### Accessibility
Built-in a11y addon checks automatically

## 📁 File Structure

```
stories/
├── components/              # Component stories
│   ├── Badge.stories.tsx
│   ├── Card.stories.tsx
│   └── ...
├── pages/                   # Page stories
│   ├── Dashboard.stories.tsx
│   ├── Deployments.stories.tsx
│   └── Vulnerabilities.stories.tsx
├── mocks/                   # Mock data
│   ├── mockData.ts
│   ├── queryProvider.tsx
│   └── index.ts
└── README.md
```

## 🔍 Troubleshooting

### Story Not Loading
```
1. Check imports are correct
2. Verify mock data structure
3. Check browser console
4. Ensure decorators are applied
```

### Mock Data Not Working
```
1. Verify query key patterns
2. Check QueryClient is provided
3. Ensure mock data matches expected types
4. Console.log queryKey in decorator
```

### TypeScript Errors
```
1. Import types from @/lib/api
2. Check all required props
3. Verify decorator types
4. Run: npx tsc --noEmit
```

### Styling Issues
```
1. Check globals.css is imported
2. Verify Tailwind config
3. Apply proper decorators
4. Check dark mode classes
```

## 📚 Resources

- **Storybook Docs**: https://storybook.js.org/docs
- **React Query**: https://tanstack.com/query/latest
- **Mock Data**: `/stories/mocks/mockData.ts`
- **Full Docs**: `/stories/README.md`

## 💡 Pro Tips

1. **Use Controls**: Interactive props in Storybook UI
2. **Add Descriptions**: Document what each story shows
3. **Test Edge Cases**: Empty, loading, error states
4. **Keep it Simple**: One concept per story
5. **Reuse Decorators**: Share common setup
6. **Type Everything**: Full TypeScript support
7. **Mock Realistically**: Use factory functions
8. **Test Accessibility**: Enable a11y addon

## 🎯 Quick Commands

```bash
# Development
npm run storybook          # Start dev server

# Build
npm run build-storybook    # Build static site

# Test
npm run test-storybook     # Run tests
npm run chromatic          # Visual regression

# Lint stories
npx eslint stories/
```

---

**Need Help?** Check `/stories/README.md` for detailed documentation.
