# InfraPilot Frontend Revamp Plan

**Date**: 2026-01-15
**Status**: 🚧 IN PROGRESS
**Strategic Goal**: Transform InfraPilot's UI from "feature-complete" to "enterprise-grade"

---

## Executive Summary

InfraPilot is functionally ahead of most DevSecOps tools. The risk is that the UX/UI does not communicate that power. Enterprise buyers and YC partners judge in 30-60 seconds based on UI clarity.

**The Problem**: Tool-centric navigation, inconsistent page patterns, technical jargon
**The Solution**: Risk-centric IA, standardized 4-section layout, enterprise visual language
**The Timeline**: 3-4 weeks, frontend-only, no new features
**The Outcome**: Demo-ready for enterprise buyers, YC partners, and investors

---

## UX North Star (Very Important)

InfraPilot UI should answer exactly 3 questions, everywhere:

1. **What's risky right now?**
2. **Who owns it?**
3. **What should I do next?**

If a screen doesn't help answer one of these → remove or simplify it.

---

## The 4-Section Golden Pattern

Every major page follows this enterprise-standard layout:

### 1. Header (Context)
- Page title + description
- Service/Project/Environment context
- Owner information
- Risk status (color + icon)
- Primary action button

### 2. Key Metrics (Scan-Friendly)
- 3-5 KPIs maximum
- Big numbers, clear labels
- Icons for visual hierarchy
- Trend indicators (optional)
- No charts in this section

### 3. Primary Table
- Search + filters visible immediately
- Sortable columns
- Row click → detail panel
- Empty state with next action
- Loading state (skeleton)
- Pagination

### 4. Right-Side Detail Panel
- Slide-over panel (not modal)
- Opens on row click
- Shows: Evidence, Timeline, Actions
- Avoids page hopping
- Feels very enterprise

---

## New Information Architecture

### Current Sidebar (Tool-Centric) ❌
```
- Overview
- Security
- Platform Security
- Security Maturity
- Code Quality
- Containers
- Deployments
- Webhooks
- Policies
- Vulnerabilities
- SBOMs
- Developer Feedback
- Risk Exceptions
- Ownership & Teams
- Networks
- Volumes
- Images
- Proxies
- Logs
- Alerts
- Health
- Users
- Settings
```

### New Sidebar (Risk-Centric) ✅
```
📊 OVERVIEW
  - Dashboard
  - Security Posture

🔨 BUILD (Shift-Left)
  - Code Quality
  - Developer Feedback
  - Policies

📦 DEPLOY
  - Deployments
  - Images
  - SBOMs
  - Vulnerabilities

▶️ RUN
  - Runtime Security
  - Containers
  - Logs
  - Alerts

⚖️ GOVERN
  - Risk Exceptions
  - Teams & Ownership
  - Security Maturity
  - Webhooks

⚙️ PLATFORM
  - Platform Security
  - Proxies
  - Networks
  - Volumes
  - Health
  - Users
  - Settings
```

**Why This Works**:
- Groups by user intent, not technical features
- Mirrors DevSecOps lifecycle (Build → Deploy → Run → Govern)
- Reduces cognitive load
- Feels enterprise

---

## Visual Language

### Color Palette (Semantic, Conservative)

**Severity Colors**:
- 🔴 **Critical**: Red (#DC2626) - Immediate action required
- 🟠 **High**: Orange (#EA580C) - Fix soon
- 🟡 **Medium**: Yellow (#CA8A04) - Track
- 🔵 **Low**: Blue (#2563EB) - Informational
- ⚪ **Info**: Gray (#6B7280) - FYI

**Status Colors**:
- 🟢 **Healthy**: Green (#16A34A) - All good
- 🟡 **Warning**: Yellow (#CA8A04) - Attention needed
- 🟠 **Degraded**: Orange (#EA580C) - Issues present
- 🔴 **Critical**: Red (#DC2626) - Major issues

**Neutral Palette**:
- Backgrounds: Gray 50, 100, 900, 950
- Text: Gray 900 (dark mode: white), Gray 500 (secondary)
- Borders: Gray 200 (dark mode: Gray 800)

**Design Principles**:
- ❌ No gradients
- ❌ No neon colors
- ❌ No excessive shadows
- ✅ Calm, professional
- ✅ High contrast for accessibility
- ✅ Consistent across light/dark modes

### Typography

**Scale**:
- H1: 3xl (30px) - Bold - Page titles
- H2: 2xl (24px) - Semibold - Section headers
- H3: xl (20px) - Semibold - Card headers
- H4: lg (18px) - Medium - Sub-headers
- Body: base (16px) - Normal - Primary text
- Caption: sm (14px) - Normal - Secondary text
- Small: xs (12px) - Normal - Labels

**Principles**:
- Use system font stack (no custom fonts)
- Bold for emphasis only
- Consistent line heights (1.5 for body, 1.2 for headings)
- Clear hierarchy

### Spacing

**Scale**: 4px, 8px, 12px, 16px, 24px, 32px, 48px, 64px

**Usage**:
- Component padding: 16px (md)
- Section spacing: 24px (lg)
- Page margins: 32px (xl)
- Card padding: 24px (lg)
- Table cell padding: 12px (sm)

### Shadows (Use Sparingly)

**Scale**:
- Subtle: 0 1px 2px rgba(0,0,0,0.05) - Borders, separators
- Medium: 0 4px 6px rgba(0,0,0,0.1) - Cards, dropdowns
- Large: 0 10px 15px rgba(0,0,0,0.1) - Modals, slide-overs

**Usage**: Only for cards, modals, slide-overs, and dropdowns

---

## Component Library

### Foundation Components (14 total)

**Priority 1: Core Components**

1. **Badge** (`components/ui/Badge.tsx`)
   - Variants: severity, status, default
   - Sizes: sm, md, lg
   - With/without icon
   - Purpose: Severity indicators, status labels

2. **Card** (`components/ui/Card.tsx`)
   - Variants: default, elevated, bordered
   - Sections: header, body, footer
   - Interactive states
   - Purpose: Container for content sections

3. **Table** (`components/ui/Table.tsx`)
   - Sticky header
   - Row selection
   - Click-to-expand
   - Empty state
   - Loading state (skeleton)
   - Pagination
   - Purpose: Primary data display

4. **SlideOver** (`components/ui/SlideOver.tsx`)
   - Replaces modals for details
   - Sizes: sm, md, lg, xl
   - Close button
   - Overlay with click-to-close
   - Purpose: Detail panels

5. **StatCard** (`components/ui/StatCard.tsx`)
   - Large number display
   - Label + description
   - Icon (optional)
   - Trend indicator
   - Color variants
   - Purpose: KPI display

6. **EmptyState** (`components/ui/EmptyState.tsx`)
   - Icon
   - Heading + description
   - Primary action CTA
   - Variants: no-data, no-results, error
   - Purpose: Communicate empty states clearly

7. **PageHeader** (`components/ui/PageHeader.tsx`)
   - Title + description
   - Breadcrumbs (optional)
   - Primary action button
   - Secondary actions
   - Status badge
   - Purpose: Page context

8. **SeverityBadge** (`components/ui/SeverityBadge.tsx`)
   - Standardized severity display
   - Icon + text
   - Color-coded
   - Accessible
   - Purpose: Risk communication

9. **StatusIndicator** (`components/ui/StatusIndicator.tsx`)
   - Dot + label
   - Colors: green, yellow, orange, red
   - Pulse animation
   - Purpose: Real-time status

10. **Skeleton** (`components/ui/Skeleton.tsx`)
    - Card skeleton
    - Table skeleton
    - Text skeleton
    - Purpose: Loading states

11. **Spinner** (`components/ui/Spinner.tsx`)
    - Inline spinner
    - Full-page spinner
    - Sizes: sm, md, lg
    - Purpose: Loading indicators

**Priority 2: Complex Components**

12. **FilterPanel** (`components/ui/FilterPanel.tsx`)
    - Collapsible
    - Multiple filter types
    - Active filter badges
    - Clear all action
    - Purpose: Table filtering

13. **DetailPanel** (`components/ui/DetailPanel.tsx`)
    - Label/value pairs
    - Section headers
    - Code blocks
    - Action buttons
    - Timeline view
    - Purpose: Entity details

14. **Timeline** (`components/ui/Timeline.tsx`)
    - Vertical timeline
    - Event cards
    - Timestamp formatting
    - User attribution
    - Purpose: Audit history

### Page Patterns

**StandardPageLayout** (`components/patterns/StandardPageLayout.tsx`)
- Implements 4-section golden pattern
- Consistent across all pages
- Props: header, metrics, table, detailPanel

**MetricsGrid** (`components/patterns/MetricsGrid.tsx`)
- Grid layout for StatCards
- Responsive (1 col mobile, 2 col tablet, 4 col desktop)

**TableSection** (`components/patterns/TableSection.tsx`)
- FilterPanel + Table + Pagination
- Consistent table wrapper

---

## Storybook Structure

```
frontend/stories/

  foundations/
    Colors.stories.tsx              # Color palette showcase
    Typography.stories.tsx          # Type scale + examples
    Spacing.stories.tsx             # Spacing scale
    Shadows.stories.tsx             # Shadow examples
    Icons.stories.tsx               # Icon library

  components/
    Badge.stories.tsx               # All badge variants
    Card.stories.tsx                # All card variants
    Table.stories.tsx               # Table with data
    SlideOver.stories.tsx           # Slide-over examples
    StatCard.stories.tsx            # KPI card examples
    EmptyState.stories.tsx          # Empty state variants
    PageHeader.stories.tsx          # Header variants
    SeverityBadge.stories.tsx       # Severity examples
    StatusIndicator.stories.tsx     # Status examples
    Skeleton.stories.tsx            # Loading states
    Spinner.stories.tsx             # Spinner variants
    FilterPanel.stories.tsx         # Filter examples
    DetailPanel.stories.tsx         # Detail examples
    Timeline.stories.tsx            # Timeline examples

  patterns/
    StandardPageLayout.stories.tsx  # Full page pattern
    MetricsGrid.stories.tsx         # Metrics layout
    TableSection.stories.tsx        # Table pattern

  pages/
    SecurityDashboard.stories.tsx   # Full page example
    Vulnerabilities.stories.tsx     # Full page example
    Deployments.stories.tsx         # Full page example
    RuntimeSecurity.stories.tsx     # Full page example
```

---

## Implementation Phases

### Phase 0: Foundation & Setup (2 days)

**Deliverables**:
- ✅ Storybook installed and configured
- ✅ Design tokens file created
- ✅ Design system documentation
- ✅ Directory structure established

**Tasks**:
- [ ] Install Storybook for Next.js 14
- [ ] Configure Tailwind integration
- [ ] Set up dark mode support
- [ ] Create design-tokens.ts
- [ ] Create design-system.md
- [ ] Set up stories directory

---

### Phase 1: Component Library (5 days)

**Deliverables**:
- ✅ 14 reusable components
- ✅ All components in Storybook
- ✅ TypeScript types for all props
- ✅ Component documentation

**Day 1-2: Foundation Components**
- [ ] Badge
- [ ] Card
- [ ] StatCard
- [ ] EmptyState
- [ ] PageHeader

**Day 3-4: Data Components**
- [ ] Table
- [ ] SlideOver
- [ ] SeverityBadge
- [ ] StatusIndicator
- [ ] Skeleton
- [ ] Spinner

**Day 5: Complex Components**
- [ ] FilterPanel
- [ ] DetailPanel
- [ ] Timeline

---

### Phase 2: Information Architecture (3 days)

**Deliverables**:
- ✅ Reorganized sidebar with sections
- ✅ Section dividers and labels
- ✅ Updated navigation styling
- ✅ Before/after screenshots

**Tasks**:
- [ ] Update layout.tsx with new structure
- [ ] Implement section dividers
- [ ] Add section labels
- [ ] Update active/hover states
- [ ] Test navigation flow

---

### Phase 3: Page Refactoring (7 days)

**Deliverables**:
- ✅ 10 refactored pages
- ✅ All pages follow 4-section pattern
- ✅ Consistent components used
- ✅ Cross-links implemented

**Week 2 (4 pages)**:
- [ ] Security Dashboard (`/security`) - Day 1
- [ ] Vulnerabilities (`/vulnerabilities`) - Day 2
- [ ] Deployments (`/deployments`) - Day 3
- [ ] Runtime Security (`/runtime-security`) - Day 4

**Week 3 (6 pages)**:
- [ ] Platform Security (`/platform-security`) - Day 1
- [ ] Code Quality (`/code-quality`) - Day 2
- [ ] Risk Exceptions (`/exceptions`) - Day 3
- [ ] Policies (`/policies`) - Day 4
- [ ] SBOMs (`/sboms`) - Day 5
- [ ] Teams & Ownership (`/ownership`) - Day 6

**Per Page Checklist**:
- [ ] Replace custom components with design system
- [ ] Implement 4-section layout (Header, Metrics, Table, Detail)
- [ ] Add owner/context to header
- [ ] Add primary action button
- [ ] Convert to SlideOver detail panel
- [ ] Add empty states
- [ ] Improve loading states
- [ ] Add cross-links to related entities
- [ ] Update copy for clarity

---

### Phase 4: Visual Polish (3 days)

**Deliverables**:
- ✅ Semantic color system applied
- ✅ Consistent typography
- ✅ Consistent spacing
- ✅ Interaction states defined
- ✅ Before/after screenshots

**Tasks**:
- [ ] Define semantic colors in Tailwind config
- [ ] Apply severity/status color mappings
- [ ] Ensure WCAG AA contrast
- [ ] Define and apply type scale
- [ ] Define and apply spacing scale
- [ ] Add hover/focus/active states
- [ ] Define shadow usage
- [ ] Update all pages with new styles

---

### Phase 5: Content & Copy (2 days)

**Deliverables**:
- ✅ Copy guidelines document
- ✅ All pages reviewed for clarity
- ✅ Consistent terminology
- ✅ User-friendly error messages

**Tasks**:
- [ ] Audit all error messages
- [ ] Add/improve empty states
- [ ] Update page descriptions
- [ ] Review button labels
- [ ] Add help text/tooltips
- [ ] Create glossary of terms

**Copy Principles**:
- ❌ "Policy decision: deny"
- ✅ "Deployment blocked due to critical vulnerabilities"
- ❌ "CVE-2024-12345 detected"
- ✅ "OpenSSL vulnerability affecting encryption"

---

### Phase 6: Cross-Linking (2 days)

**Deliverables**:
- ✅ EntityLink component
- ✅ All pages have cross-links
- ✅ Navigation feels like a graph
- ✅ Breadcrumbs on detail views

**Cross-Linking Map**:
```
Vulnerability →
  ├─ Deployment(s) affected
  ├─ SBOM containing package
  ├─ Exception (if exists)
  └─ Team owner

Deployment →
  ├─ Vulnerabilities detected
  ├─ Policy evaluations
  ├─ Runtime drift events
  ├─ Service ownership
  └─ Code quality results

Exception →
  ├─ Vulnerability/Risk
  ├─ Deployment
  ├─ Requester
  ├─ Approver
  └─ Audit timeline

Policy →
  ├─ Recent decisions
  ├─ Affected deployments
  └─ Violation history
```

---

### Phase 7: Testing & Demo Prep (5 days)

**Deliverables**:
- ✅ Accessibility audit passed
- ✅ Responsive design tested
- ✅ Performance optimized
- ✅ Demo-ready environment
- ✅ Screenshot library
- ✅ Demo video

**Tasks**:
- [ ] Keyboard navigation audit
- [ ] Screen reader testing
- [ ] WCAG AA contrast check
- [ ] Mobile/tablet responsive testing
- [ ] Performance profiling
- [ ] Browser testing (Chrome, Firefox, Safari, Edge)
- [ ] Create demo data seed
- [ ] Screenshot all pages
- [ ] Record demo video (2-3 min)
- [ ] Prepare demo script

---

## File Structure (After Revamp)

```
frontend/

  components/
    ui/                              # Design System Components
      Badge.tsx
      Card.tsx
      Table.tsx
      SlideOver.tsx
      StatCard.tsx
      EmptyState.tsx
      PageHeader.tsx
      SeverityBadge.tsx
      StatusIndicator.tsx
      Skeleton.tsx
      Spinner.tsx
      FilterPanel.tsx
      DetailPanel.tsx
      Timeline.tsx
      EntityLink.tsx

    patterns/                        # Page Patterns
      StandardPageLayout.tsx
      MetricsGrid.tsx
      TableSection.tsx

  lib/
    design-tokens.ts                 # Design Tokens
    design-system.md                 # Design System Docs

  stories/                           # Storybook Stories
    foundations/
      Colors.stories.tsx
      Typography.stories.tsx
      Spacing.stories.tsx
      Shadows.stories.tsx
      Icons.stories.tsx

    components/
      Badge.stories.tsx
      Card.stories.tsx
      Table.stories.tsx
      SlideOver.stories.tsx
      StatCard.stories.tsx
      EmptyState.stories.tsx
      PageHeader.stories.tsx
      SeverityBadge.stories.tsx
      StatusIndicator.stories.tsx
      Skeleton.stories.tsx
      Spinner.stories.tsx
      FilterPanel.stories.tsx
      DetailPanel.stories.tsx
      Timeline.stories.tsx

    patterns/
      StandardPageLayout.stories.tsx
      MetricsGrid.stories.tsx
      TableSection.stories.tsx

    pages/
      SecurityDashboard.stories.tsx
      Vulnerabilities.stories.tsx
      Deployments.stories.tsx
      RuntimeSecurity.stories.tsx

  app/
    (dashboard)/
      security/page.tsx              # Refactored pages
      vulnerabilities/page.tsx
      deployments/page.tsx
      runtime-security/page.tsx
      platform-security/page.tsx
      code-quality/page.tsx
      exceptions/page.tsx
      policies/page.tsx
      sboms/page.tsx
      ownership/page.tsx
      layout.tsx                     # Updated navigation
```

---

## Success Criteria

### Quantitative Metrics

- [ ] **100%** of major pages follow 4-section golden pattern
- [ ] **14+** reusable components in Storybook
- [ ] **0** accessibility violations (WCAG AA)
- [ ] **<3 clicks** to action on any risk
- [ ] **<2s** page load time on all pages
- [ ] **100%** dark mode compatibility

### Qualitative Metrics

- [ ] Can answer "What's risky?" in **<10 seconds** on any page
- [ ] Can identify owner in **<5 seconds**
- [ ] Can take action in **<3 clicks**
- [ ] Feels calm, professional, trustworthy
- [ ] Demo-ready for enterprise buyers

### Business Impact

- [ ] YC partner demo readiness
- [ ] Enterprise sales demo readiness
- [ ] Investor pitch deck screenshots
- [ ] Marketing website screenshots
- [ ] User confidence in platform security
- [ ] Reduced time-to-value for new users

---

## Design References (Inspiration, Not Copy)

**Enterprise DevSecOps Tools** (study their UX patterns):
- Snyk: Clear severity indicators, scannable metrics
- Datadog Security: Clean layouts, strong hierarchy
- GitHub Advanced Security: Excellent cross-linking
- Wiz: Calm colors, professional feel

**Key Patterns to Borrow**:
- Calm layouts (no gradients, minimal animation)
- Dense but readable tables
- Strong visual hierarchy
- Consistent interaction patterns
- Cross-linking as a core UX principle

---

## Risk Mitigation

### Technical Risks

**Risk**: Breaking existing functionality during refactor
**Mitigation**:
- Refactor one page at a time
- Keep old components until migration complete
- Test each page thoroughly before moving to next

**Risk**: Storybook slows down development
**Mitigation**:
- Build components in Storybook first (faster iteration)
- Use Storybook as development environment
- Run Storybook in parallel with Next.js

**Risk**: Design system becomes bloated
**Mitigation**:
- Only create components used 3+ times
- Delete unused components monthly
- Keep component API minimal

### Schedule Risks

**Risk**: 3-4 weeks too aggressive
**Mitigation**:
- Prioritize: Security Dashboard, Vulnerabilities, Deployments first
- Other pages can follow later
- 80/20 rule: Perfect top 3 pages, good enough for rest

**Risk**: Scope creep (adding new features)
**Mitigation**:
- **NO NEW FEATURES** during revamp
- Document feature requests for post-revamp
- Focus on UX only

---

## Post-Revamp Maintenance

### Design System Governance

**Component Review Process**:
1. New component request submitted
2. Check if existing component can be extended
3. If truly new, build in Storybook first
4. Review with team before merging
5. Document in design-system.md

**Monthly Audit**:
- Review component usage
- Delete unused components
- Update Storybook examples
- Check accessibility compliance

### Documentation Updates

- Keep design-system.md current
- Update Storybook stories when components change
- Screenshot library updated quarterly
- Demo video refreshed every 6 months

---

## Appendix: Copy Guidelines

### Voice & Tone

**Voice** (consistent across platform):
- Professional but approachable
- Clear and direct
- Technical accuracy without jargon
- Action-oriented

**Tone** (varies by context):
- **Dashboard**: Informative, calm
- **Errors**: Helpful, not alarming
- **Success**: Encouraging, brief
- **Empty states**: Friendly, guiding

### Terminology Standards

**Use This** → **Not This**:
- Deployment → Stack/Service
- Container → Docker container
- Vulnerability → CVE/Security issue
- Critical severity → High priority
- Blocked → Denied/Rejected
- Owner → Responsible team
- Exception → Waiver/Exemption

### Button Label Patterns

- **Create** [Entity] (not "Add" or "New")
- **View Details** (not "More" or "See More")
- **Resolve** [Issue] (not "Mark as Resolved")
- **Approve** [Request] (not "Accept")
- **Deploy** [Service] (not "Push" or "Release")

### Error Message Template

```
[What happened] [Why it happened] [What to do next]

Example:
"Deployment blocked. 3 critical vulnerabilities detected. Review vulnerabilities or request an exception to proceed."

Not:
"Error: policy_deny"
```

### Empty State Template

```
[Icon]
[No [Entity] yet]
[Brief explanation]
[Primary action button]

Example:
[Shield icon]
"No risk exceptions yet"
"This means all deployments are policy-compliant. 🎉"
[Request Exception]
```

---

## Appendix: Accessibility Checklist

### Keyboard Navigation
- [ ] All interactive elements focusable
- [ ] Focus order is logical
- [ ] Focus indicators clearly visible
- [ ] No keyboard traps
- [ ] Skip links for main content

### Screen Reader Support
- [ ] All images have alt text
- [ ] ARIA labels for icon-only buttons
- [ ] ARIA live regions for dynamic content
- [ ] Heading hierarchy is logical
- [ ] Form labels properly associated

### Color & Contrast
- [ ] All text meets WCAG AA contrast (4.5:1)
- [ ] Large text meets WCAG AA (3:1)
- [ ] Information not conveyed by color alone
- [ ] Focus indicators meet contrast requirements

### Responsive & Mobile
- [ ] Touch targets at least 44x44px
- [ ] Text readable without zoom
- [ ] Horizontal scrolling only where appropriate
- [ ] Orientation agnostic (portrait/landscape)

---

## Appendix: Performance Checklist

### Bundle Size
- [ ] Code splitting by route
- [ ] Lazy load heavy components
- [ ] Tree-shake unused code
- [ ] Optimize dependencies

### Runtime Performance
- [ ] Virtualize long lists (>100 rows)
- [ ] Debounce search/filter inputs
- [ ] Memoize expensive computations
- [ ] Optimize re-renders with React.memo

### Loading Performance
- [ ] Optimize images (WebP, proper sizing)
- [ ] Preload critical resources
- [ ] Lazy load below-the-fold content
- [ ] Server-side rendering for initial load

### Metrics to Track
- [ ] First Contentful Paint < 1.8s
- [ ] Largest Contentful Paint < 2.5s
- [ ] Time to Interactive < 3.8s
- [ ] Cumulative Layout Shift < 0.1

---

## Timeline Summary

```
Week 1
├─ Days 1-2: Phase 0 (Foundation & Setup)
├─ Days 3-7: Phase 1 (Component Library)

Week 2
├─ Days 1-3: Phase 2 (Information Architecture)
├─ Days 4-7: Phase 3 Part 1 (4 pages: Security, Vulns, Deployments, Runtime)

Week 3
├─ Days 1-6: Phase 3 Part 2 (6 pages: Platform, Code, Exceptions, Policies, SBOMs, Ownership)
├─ Day 7: Phase 4 (Visual Polish)

Week 4
├─ Days 1-2: Phase 5 (Content & Copy)
├─ Days 3-4: Phase 6 (Cross-Linking)
├─ Day 5: Phase 7 (Testing & Demo Prep)
```

**Total**: 3-4 weeks, frontend-only, no new features

---

## Status Tracking

### Phase 0: Foundation & Setup
- [ ] Storybook installed
- [ ] Design tokens created
- [ ] Design system docs created
- [ ] Directory structure created

### Phase 1: Component Library
- [ ] Badge
- [ ] Card
- [ ] Table
- [ ] SlideOver
- [ ] StatCard
- [ ] EmptyState
- [ ] PageHeader
- [ ] SeverityBadge
- [ ] StatusIndicator
- [ ] Skeleton
- [ ] Spinner
- [ ] FilterPanel
- [ ] DetailPanel
- [ ] Timeline

### Phase 2: Information Architecture
- [ ] Sidebar reorganized
- [ ] Section dividers added
- [ ] Navigation styling updated

### Phase 3: Page Refactoring
- [ ] Security Dashboard
- [ ] Vulnerabilities
- [ ] Deployments
- [ ] Runtime Security
- [ ] Platform Security
- [ ] Code Quality
- [ ] Risk Exceptions
- [ ] Policies
- [ ] SBOMs
- [ ] Teams & Ownership

### Phase 4: Visual Polish
- [ ] Color system applied
- [ ] Typography standardized
- [ ] Spacing standardized
- [ ] Interaction states defined

### Phase 5: Content & Copy
- [ ] Copy guidelines created
- [ ] Error messages updated
- [ ] Empty states improved
- [ ] Terminology standardized

### Phase 6: Cross-Linking
- [ ] EntityLink component created
- [ ] Cross-links added to all pages
- [ ] Breadcrumbs added

### Phase 7: Testing & Demo
- [ ] Accessibility audit passed
- [ ] Responsive design tested
- [ ] Performance optimized
- [ ] Demo environment ready
- [ ] Screenshot library created
- [ ] Demo video recorded

---

**Last Updated**: 2026-01-15
**Next Review**: After Phase 1 completion
**Owner**: Development Team
**Status**: 🚧 Ready to Begin Phase 0
