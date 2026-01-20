# InfraPilot Developer Workflow

**Last Updated**: 2026-01-15

---

## Quick Start

### Option 1: Integrated Development (Recommended)

Start everything (database, backend, frontend, and Storybook) with one command:

```bash
./scripts/dev.sh dev
```

This starts:
- 📊 **Dashboard**: http://localhost:3000
- 🔌 **API**: http://localhost:8080/api/v1
- 📖 **Storybook**: http://localhost:6006

**Stop all services:**
```bash
./scripts/dev.sh dev:stop
```

**View logs:**
```bash
./scripts/dev.sh dev:logs
```

---

### Option 2: Docker Development

Start all services in Docker:

```bash
./scripts/dev.sh up
```

Access:
- **Dashboard**: http://localhost
- **API**: http://localhost/api/v1

**View logs:**
```bash
./scripts/dev.sh logs backend    # Backend logs
./scripts/dev.sh logs frontend   # Frontend logs
./scripts/dev.sh logs            # All logs
```

**Stop services:**
```bash
./scripts/dev.sh down
```

---

### Option 3: Manual (Fine-Grained Control)

**1. Start database services:**
```bash
./scripts/dev.sh up:db
```

**2. Start backend:**
```bash
cd backend
go run ./cmd/server
```

**3. Start frontend:**
```bash
cd frontend
pnpm dev
```

**4. Start Storybook (optional):**
```bash
cd frontend
pnpm storybook
```

---

## Storybook Development

### What is Storybook?

Storybook is an isolated component development environment. It allows you to:
- Build UI components in isolation
- Test all component states and variants
- Document component APIs
- Catch UI bugs before they reach production
- Share components with designers and stakeholders

### When to Use Storybook

**✅ Use Storybook for:**
- Building new UI components (Badge, Card, Table, etc.)
- Testing component variants (colors, sizes, states)
- Documenting component props and usage
- Visual regression testing
- Design system development

**❌ Don't use Storybook for:**
- Testing business logic (use unit tests)
- Integration testing (use E2E tests)
- API testing (use backend tests)

### Storybook Workflow

#### 1. Start Storybook

**Standalone:**
```bash
./scripts/dev.sh storybook
```

**Or with full dev environment:**
```bash
./scripts/dev.sh dev
```

Then open: http://localhost:6006

#### 2. Create a Component

Create your component in `frontend/components/ui/`:

```tsx
// frontend/components/ui/Button.tsx
import React from 'react';
import { cn } from '@/lib/design-tokens';

export interface ButtonProps {
  variant?: 'primary' | 'secondary';
  size?: 'sm' | 'md' | 'lg';
  children: React.ReactNode;
  onClick?: () => void;
}

export function Button({ variant = 'primary', size = 'md', children, onClick }: ButtonProps) {
  return (
    <button
      onClick={onClick}
      className={cn(
        'rounded-lg font-medium',
        variant === 'primary' && 'bg-primary-600 text-white',
        variant === 'secondary' && 'bg-gray-200 text-gray-900',
        size === 'sm' && 'px-3 py-1.5 text-sm',
        size === 'md' && 'px-4 py-2 text-base',
        size === 'lg' && 'px-6 py-3 text-lg'
      )}
    >
      {children}
    </button>
  );
}
```

#### 3. Create a Story

Create a story in `frontend/stories/components/`:

```tsx
// frontend/stories/components/Button.stories.tsx
import type { Meta, StoryObj } from '@storybook/react';
import { Button } from '@/components/ui/Button';

const meta: Meta<typeof Button> = {
  title: 'Components/Button',
  component: Button,
  parameters: {
    layout: 'centered',
  },
  tags: ['autodocs'],
};

export default meta;
type Story = StoryObj<typeof Button>;

export const Primary: Story = {
  args: {
    children: 'Primary Button',
    variant: 'primary',
  },
};

export const Secondary: Story = {
  args: {
    children: 'Secondary Button',
    variant: 'secondary',
  },
};

export const AllSizes: Story = {
  render: () => (
    <div className="flex gap-4">
      <Button size="sm">Small</Button>
      <Button size="md">Medium</Button>
      <Button size="lg">Large</Button>
    </div>
  ),
};
```

#### 4. View in Storybook

Open http://localhost:6006 and navigate to **Components → Button** in the sidebar.

You'll see:
- All your component variants
- Interactive controls to change props
- Auto-generated documentation
- Component source code

#### 5. Test Accessibility

Storybook includes the a11y addon. Check the **Accessibility** tab to ensure:
- WCAG AA compliance
- Proper contrast ratios
- Keyboard navigation
- Screen reader support

#### 6. Use in Application

Once your component is ready, use it in your pages:

```tsx
// frontend/app/(dashboard)/security/page.tsx
import { Button } from '@/components/ui/Button';

export default function SecurityPage() {
  return (
    <div>
      <h1>Security Dashboard</h1>
      <Button variant="primary" onClick={handleRefresh}>
        Refresh Data
      </Button>
    </div>
  );
}
```

---

## Design System Guidelines

### Use Design Tokens

Always use design tokens instead of hard-coded values:

```tsx
// ❌ Bad
<div className="px-4 py-2 bg-red-600 text-white">Critical</div>

// ✅ Good
import { getSeverityColor } from '@/lib/design-tokens';

const colors = getSeverityColor('critical');
<div className={`px-4 py-2 ${colors.bg} ${colors.text}`}>Critical</div>

// ✅ Even Better (use SeverityBadge component)
import { SeverityBadge } from '@/components/ui/Badge';
<SeverityBadge severity="critical">Critical</SeverityBadge>
```

### Component Checklist

Before marking a component as "done", ensure:
- [ ] Uses design tokens (no hard-coded colors/spacing)
- [ ] Supports dark mode
- [ ] Keyboard accessible
- [ ] WCAG AA compliant
- [ ] Has Storybook stories
- [ ] Has all variants documented
- [ ] TypeScript types defined
- [ ] Responsive design tested

---

## Common Tasks

### Database Operations

**Reset database:**
```bash
./scripts/dev.sh reset
```

**Run migrations:**
```bash
./scripts/dev.sh migrate
```

**Seed test data:**
```bash
./scripts/dev.sh seed
```

### Code Generation

**Generate protobuf code:**
```bash
./scripts/dev.sh proto
```

### Viewing Logs

**Docker logs:**
```bash
./scripts/dev.sh logs              # All logs
./scripts/dev.sh logs backend      # Backend only
./scripts/dev.sh logs frontend     # Frontend only
```

**Local dev logs:**
```bash
./scripts/dev.sh dev:logs          # Interactive log viewer
tail -f .dev-logs/backend.log      # Backend logs
tail -f .dev-logs/frontend.log     # Frontend logs
tail -f .dev-logs/storybook.log    # Storybook logs
```

---

## Troubleshooting

### Port Already in Use

If ports 3000, 6006, or 8080 are already in use:

```bash
# Find process using port
lsof -i :3000
lsof -i :6006
lsof -i :8080

# Kill process
kill -9 <PID>

# Or stop all services and restart
./scripts/dev.sh dev:stop
./scripts/dev.sh dev
```

### Storybook Not Starting

**Check if Storybook is installed:**
```bash
cd frontend
ls -la node_modules/.bin/storybook
```

**Reinstall if needed:**
```bash
cd frontend
pnpm install
```

**Start Storybook manually:**
```bash
cd frontend
pnpm storybook
```

### Frontend Build Errors

**Clear Next.js cache:**
```bash
cd frontend
rm -rf .next
pnpm dev
```

**Reinstall dependencies:**
```bash
cd frontend
rm -rf node_modules pnpm-lock.yaml
pnpm install
```

### Database Connection Errors

**Ensure database is running:**
```bash
./scripts/dev.sh up:db
```

**Check database logs:**
```bash
./scripts/dev.sh logs postgres
```

**Reset database:**
```bash
./scripts/dev.sh reset
```

---

## Best Practices

### Component Development

1. **Start in Storybook** - Build components in isolation first
2. **Use design tokens** - Never hard-code colors or spacing
3. **Test all states** - Loading, error, empty, success
4. **Test dark mode** - Every component should work in dark mode
5. **Test accessibility** - Keyboard nav, screen readers, contrast
6. **Document props** - Use JSDoc comments for TypeScript props

### Git Workflow

1. **Pull latest main:**
```bash
git checkout main
git pull origin main
```

2. **Create feature branch:**
```bash
git checkout -b feature/badge-component
```

3. **Commit frequently:**
```bash
git add .
git commit -m "feat: add Badge component with severity variants"
```

4. **Push and create PR:**
```bash
git push origin feature/badge-component
# Create PR on GitHub
```

### Code Review Checklist

Before requesting review:
- [ ] All tests pass
- [ ] Component has Storybook stories
- [ ] Accessibility checked (a11y addon)
- [ ] Dark mode tested
- [ ] TypeScript types defined
- [ ] No console errors or warnings
- [ ] Responsive design works on mobile/tablet/desktop

---

## Useful Commands Reference

### Development
```bash
./scripts/dev.sh dev           # Start everything
./scripts/dev.sh dev:stop      # Stop everything
./scripts/dev.sh dev:logs      # View logs
./scripts/dev.sh storybook     # Start only Storybook
```

### Docker
```bash
./scripts/dev.sh up            # Start Docker services
./scripts/dev.sh down          # Stop Docker services
./scripts/dev.sh up:db         # Start only database
./scripts/dev.sh logs          # View Docker logs
```

### Database
```bash
./scripts/dev.sh reset         # Reset database
./scripts/dev.sh migrate       # Run migrations
./scripts/dev.sh seed          # Seed test data
```

### Code Generation
```bash
./scripts/dev.sh proto         # Generate protobuf
./scripts/dev.sh air           # Install Air (hot reload)
```

---

## Getting Help

- **Documentation**: `/docs` folder
- **Design System**: `frontend/lib/design-system.md`
- **Storybook**: http://localhost:6006
- **Issues**: https://github.com/anthropics/infrapilot-community/issues

---

**Happy coding! 🚀**
