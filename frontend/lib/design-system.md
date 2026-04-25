# InfraPilot Design System

**Version**: 1.0.0
**Last Updated**: 2026-01-15
**Status**: 🚧 In Development

---

## Overview

The InfraPilot Design System provides a consistent, accessible, and professional visual language for our DevSecOps platform. It ensures that every screen communicates:

1. **What's risky right now?**
2. **Who owns it?**
3. **What should I do next?**

---

## Design Principles

### 1. **Calm, Not Flashy**
Security tools should feel professional and trustworthy. We avoid gradients, neon colors, and excessive animations.

### 2. **Scannable by Default**
Users should be able to identify critical risks in seconds. We use:
- Clear visual hierarchy
- Color-coded severity
- Large, readable numbers
- Icon + text (not color alone)

### 3. **Action-First**
Every page has a clear primary action. Users should never wonder "what do I do next?"

### 4. **Consistent Patterns**
Same interactions work the same everywhere:
- Table row click → detail panel
- Severity badges → same colors everywhere
- Button placement → always top-right

### 5. **Enterprise-Ready**
Visual language that enterprise buyers and YC partners expect:
- Professional typography
- Conservative color palette
- Accessible (WCAG AA)
- Responsive design

---

## Color System

### Severity Colors

Used for vulnerabilities, policy violations, and risk indicators.

| Severity | Color | Usage | Hex |
|----------|-------|-------|-----|
| **Critical** | 🔴 Red | Immediate action required | #DC2626 |
| **High** | 🟠 Orange | Fix soon | #EA580C |
| **Medium** | 🟡 Yellow | Track and monitor | #CA8A04 |
| **Low** | 🔵 Blue | Informational | #2563EB |
| **Info** | ⚪ Gray | FYI only | #6B7280 |

**Usage Example**:
```tsx
import { severityColors } from '@/lib/design-tokens';

<span className={severityColors.critical.text}>
  Critical Vulnerability
</span>
```

### Status Colors

Used for system health, security posture, and operational status.

| Status | Color | Usage | Hex |
|--------|-------|-------|-----|
| **Healthy** | 🟢 Green | All systems operational | #16A34A |
| **Warning** | 🟡 Yellow | Attention needed | #CA8A04 |
| **Degraded** | 🟠 Orange | Issues present | #EA580C |
| **Critical** | 🔴 Red | Major issues | #DC2626 |

### Neutral Colors

| Usage | Light Mode | Dark Mode |
|-------|------------|-----------|
| **Background Primary** | White (#FFFFFF) | Gray 950 (#030712) |
| **Background Secondary** | Gray 50 (#F9FAFB) | Gray 900 (#111827) |
| **Background Tertiary** | Gray 100 (#F3F4F6) | Gray 800 (#1F2937) |
| **Border Default** | Gray 200 (#E5E7EB) | Gray 800 (#1F2937) |
| **Text Primary** | Gray 900 (#111827) | White (#FFFFFF) |
| **Text Secondary** | Gray 500 (#6B7280) | Gray 400 (#9CA3AF) |

### Brand Colors

| Usage | Color | Hex |
|-------|-------|-----|
| **Primary** | Blue | #2563EB |
| **Primary Hover** | Darker Blue | #1D4ED8 |

---

## Typography

### Type Scale

| Level | Size | Weight | Usage |
|-------|------|--------|-------|
| **H1** | 30px (3xl) | Bold | Page titles |
| **H2** | 24px (2xl) | Semibold | Section headers |
| **H3** | 20px (xl) | Semibold | Card headers |
| **H4** | 18px (lg) | Medium | Sub-headers |
| **Body** | 16px (base) | Normal | Primary text |
| **Caption** | 14px (sm) | Normal | Secondary text |
| **Small** | 12px (xs) | Normal | Labels, badges |

### Font Stack

System fonts for optimal performance:
```css
font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
             "Helvetica Neue", Arial, sans-serif;
```

### Usage Example

```tsx
import { typography } from '@/lib/design-tokens';

<h1 className={`${typography.h1.size} ${typography.h1.weight}`}>
  Security Dashboard
</h1>
```

---

## Spacing

### Spacing Scale

| Size | Value | Usage |
|------|-------|-------|
| **xs** | 4px | Tight spacing (badge padding) |
| **sm** | 8px | Component internal spacing |
| **md** | 12px | Table cell padding |
| **lg** | 16px | Card padding, form fields |
| **xl** | 24px | Section spacing |
| **2xl** | 32px | Page margins |
| **3xl** | 48px | Large section breaks |
| **4xl** | 64px | Hero spacing |

### Usage Guidelines

- **Component padding**: Use `lg` (16px)
- **Section spacing**: Use `xl` (24px)
- **Page margins**: Use `2xl` (32px)
- **Card padding**: Use `xl` (24px)

---

## Shadows

Use sparingly for depth hierarchy.

| Level | Usage | CSS |
|-------|-------|-----|
| **None** | Flat surfaces | `shadow-none` |
| **Subtle** | Borders, separators | `shadow-sm` |
| **Medium** | Cards, dropdowns | `shadow-md` |
| **Large** | Modals, slide-overs | `shadow-lg` |
| **XL** | Top-level overlays | `shadow-xl` |

**Guidelines**:
- ✅ Cards, modals, slide-overs, dropdowns
- ❌ Buttons, badges, table rows

---

## Border Radius

| Size | Value | Usage |
|------|-------|-------|
| **None** | 0px | Table cells |
| **Default** | 4px | Inputs, small buttons |
| **MD** | 6px | Buttons |
| **LG** | 8px | Cards, panels |
| **XL** | 12px | Large cards |
| **Full** | 9999px | Pills, avatars |

---

## Components

### Badge

**Purpose**: Display severity, status, or labels

**Variants**:
- Severity: critical, high, medium, low, info
- Status: healthy, warning, degraded, critical

**Sizes**: sm, md, lg

**Usage**:
```tsx
import { SeverityBadge } from '@/components/ui/SeverityBadge';

<SeverityBadge severity="critical" />
```

### Card

**Purpose**: Container for related content

**Variants**: default, elevated, bordered

**Usage**:
```tsx
import { Card } from '@/components/ui/Card';

<Card>
  <Card.Header>
    <h3>Vulnerabilities</h3>
  </Card.Header>
  <Card.Body>
    <p>12 critical issues found</p>
  </Card.Body>
</Card>
```

### Table

**Purpose**: Display structured data

**Features**:
- Sticky header
- Row selection
- Click-to-expand
- Empty state
- Loading state

**Usage**:
```tsx
import { Table } from '@/components/ui/Table';

<Table>
  <Table.Header>
    <Table.Row>
      <Table.Head>CVE</Table.Head>
      <Table.Head>Severity</Table.Head>
    </Table.Row>
  </Table.Header>
  <Table.Body>
    <Table.Row onClick={handleClick}>
      <Table.Cell>CVE-2024-12345</Table.Cell>
      <Table.Cell><SeverityBadge severity="critical" /></Table.Cell>
    </Table.Row>
  </Table.Body>
</Table>
```

### SlideOver

**Purpose**: Display detailed information without leaving context

**Sizes**: sm (320px), md (640px), lg (768px), xl (1024px)

**Usage**:
```tsx
import { SlideOver } from '@/components/ui/SlideOver';

<SlideOver open={isOpen} onClose={handleClose} size="md">
  <SlideOver.Header>
    <h3>Vulnerability Details</h3>
  </SlideOver.Header>
  <SlideOver.Body>
    <DetailPanel data={selectedItem} />
  </SlideOver.Body>
  <SlideOver.Footer>
    <Button onClick={handleAction}>Resolve</Button>
  </SlideOver.Footer>
</SlideOver>
```

### StatCard

**Purpose**: Display key metrics prominently

**Usage**:
```tsx
import { StatCard } from '@/components/ui/StatCard';

<StatCard
  label="Critical Vulnerabilities"
  value={12}
  icon={AlertTriangle}
  trend="up"
  trendValue="+3 from last week"
/>
```

---

## Patterns

### The 4-Section Golden Pattern

Every major page follows this structure:

```tsx
<StandardPageLayout>
  {/* 1. Header (Context) */}
  <PageHeader
    title="Vulnerabilities"
    description="Critical and high severity vulnerabilities"
    status={{ label: "12 Critical", severity: "critical" }}
    owner="Security Team"
    primaryAction={{ label: "Create Exception", onClick: handleCreate }}
  />

  {/* 2. Key Metrics (Scan-Friendly) */}
  <MetricsGrid>
    <StatCard label="Critical" value={12} />
    <StatCard label="High" value={45} />
    <StatCard label="Medium" value={128} />
    <StatCard label="Resolved" value={67} />
  </MetricsGrid>

  {/* 3. Primary Table */}
  <TableSection>
    <FilterPanel />
    <Table />
  </TableSection>

  {/* 4. Detail Panel */}
  <SlideOver>
    <DetailPanel />
  </SlideOver>
</StandardPageLayout>
```

### Cross-Linking Pattern

Always link related entities:

```tsx
<EntityLink entity="deployment" id={deploymentId}>
  production-api-v2
</EntityLink>
```

---

## Accessibility

### Color Contrast

All text meets WCAG AA standards:
- Normal text: 4.5:1 minimum
- Large text (18px+): 3:1 minimum

### Keyboard Navigation

- All interactive elements are focusable
- Focus indicators are clearly visible
- Logical tab order
- No keyboard traps

### Screen Readers

- Semantic HTML
- ARIA labels for icon-only buttons
- ARIA live regions for dynamic content
- Proper heading hierarchy

---

## Dark Mode

All components support dark mode automatically via Tailwind's `dark:` prefix.

**Guidelines**:
- Test every component in both modes
- Maintain WCAG AA contrast in both modes
- Use semantic color tokens (they adapt automatically)

---

## Responsive Design

### Breakpoints

| Breakpoint | Width | Usage |
|------------|-------|-------|
| **sm** | 640px | Mobile landscape |
| **md** | 768px | Tablet portrait |
| **lg** | 1024px | Tablet landscape |
| **xl** | 1280px | Desktop |
| **2xl** | 1536px | Large desktop |

### Mobile-First Approach

Design for mobile first, then enhance for larger screens:

```tsx
<div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
  {/* 1 col mobile, 2 col tablet, 4 col desktop */}
</div>
```

---

## Performance

### Bundle Size

- Code split by route
- Lazy load heavy components
- Tree-shake unused code

### Runtime Performance

- Virtualize long lists (>100 rows)
- Debounce search/filter inputs
- Memoize expensive computations

### Loading States

Always show loading feedback:
- Skeleton for initial load
- Spinner for actions
- Disabled state during submission

---

## File Structure

```
frontend/
  components/
    ui/                    # Design system components
      Badge.tsx
      Card.tsx
      Table.tsx
      SlideOver.tsx
      StatCard.tsx
      ...
    patterns/              # Page patterns
      StandardPageLayout.tsx
      MetricsGrid.tsx
      TableSection.tsx
  lib/
    design-tokens.ts       # Design tokens
    design-system.md       # This file
  stories/               # Storybook stories
    components/
    patterns/
    pages/
```

---

## Contributing

### Adding New Components

1. Build in Storybook first
2. Use design tokens (no hard-coded values)
3. Support dark mode
4. Test accessibility (keyboard, screen reader)
5. Write Storybook stories
6. Update this documentation

### Component Checklist

- [ ] Uses design tokens
- [ ] Supports dark mode
- [ ] Keyboard accessible
- [ ] Screen reader friendly
- [ ] Responsive design
- [ ] Loading states
- [ ] Error states
- [ ] Empty states
- [ ] Storybook stories
- [ ] TypeScript types
- [ ] Documentation

---

## Resources

### External References

- [Tailwind CSS Documentation](https://tailwindcss.com/docs)
- [WCAG 2.1 Guidelines](https://www.w3.org/WAI/WCAG21/quickref/)
- [React Aria](https://react-spectrum.adobe.com/react-aria/)
- [Radix UI](https://www.radix-ui.com/)

### Internal Resources

- Design tokens: `frontend/lib/design-tokens.ts`
- Component library: `frontend/components/ui/`
- Storybook: Run `npm run storybook`

---

## Changelog

### Version 1.0.0 (2026-01-15)
- Initial design system documentation
- Design tokens defined
- Component library started
- 4-section golden pattern established

---

**Maintained by**: Development Team
**Questions**: See contributing guide or ask in team chat
