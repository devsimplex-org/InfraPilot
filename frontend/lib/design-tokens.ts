/**
 * InfraPilot Design Tokens
 *
 * Central source of truth for colors, spacing, typography, and other design values.
 * These tokens ensure consistency across the entire application.
 */

// ============================================================================
// COLORS
// ============================================================================

/**
 * Severity Colors
 * Used for vulnerability severity, policy violations, and risk indicators
 */
export const severityColors = {
  critical: {
    bg: 'bg-red-100 dark:bg-red-900/30',
    text: 'text-red-700 dark:text-red-400',
    border: 'border-red-200 dark:border-red-800',
    hex: {
      light: '#FEE2E2',
      dark: '#7F1D1D',
      text: '#B91C1C',
    },
  },
  high: {
    bg: 'bg-orange-100 dark:bg-orange-900/30',
    text: 'text-orange-700 dark:text-orange-400',
    border: 'border-orange-200 dark:border-orange-800',
    hex: {
      light: '#FFEDD5',
      dark: '#7C2D12',
      text: '#EA580C',
    },
  },
  medium: {
    bg: 'bg-yellow-100 dark:bg-yellow-900/30',
    text: 'text-yellow-700 dark:text-yellow-400',
    border: 'border-yellow-200 dark:border-yellow-800',
    hex: {
      light: '#FEF3C7',
      dark: '#713F12',
      text: '#CA8A04',
    },
  },
  low: {
    bg: 'bg-blue-100 dark:bg-blue-900/30',
    text: 'text-blue-700 dark:text-blue-400',
    border: 'border-blue-200 dark:border-blue-800',
    hex: {
      light: '#DBEAFE',
      dark: '#1E3A8A',
      text: '#2563EB',
    },
  },
  info: {
    bg: 'bg-gray-100 dark:bg-gray-800',
    text: 'text-gray-700 dark:text-gray-300',
    border: 'border-gray-200 dark:border-gray-700',
    hex: {
      light: '#F3F4F6',
      dark: '#1F2937',
      text: '#6B7280',
    },
  },
} as const;

/**
 * Status Colors
 * Used for system health, security posture, and operational status
 */
export const statusColors = {
  healthy: {
    bg: 'bg-green-100 dark:bg-green-900/30',
    text: 'text-green-700 dark:text-green-400',
    border: 'border-green-200 dark:border-green-800',
    hex: {
      light: '#D1FAE5',
      dark: '#14532D',
      text: '#16A34A',
    },
  },
  warning: {
    bg: 'bg-yellow-100 dark:bg-yellow-900/30',
    text: 'text-yellow-700 dark:text-yellow-400',
    border: 'border-yellow-200 dark:border-yellow-800',
    hex: {
      light: '#FEF3C7',
      dark: '#713F12',
      text: '#CA8A04',
    },
  },
  degraded: {
    bg: 'bg-orange-100 dark:bg-orange-900/30',
    text: 'text-orange-700 dark:text-orange-400',
    border: 'border-orange-200 dark:border-orange-800',
    hex: {
      light: '#FFEDD5',
      dark: '#7C2D12',
      text: '#EA580C',
    },
  },
  critical: {
    bg: 'bg-red-100 dark:bg-red-900/30',
    text: 'text-red-700 dark:text-red-400',
    border: 'border-red-200 dark:border-red-800',
    hex: {
      light: '#FEE2E2',
      dark: '#7F1D1D',
      text: '#B91C1C',
    },
  },
} as const;

/**
 * Neutral Colors
 * Used for backgrounds, borders, and text
 */
export const neutralColors = {
  background: {
    primary: 'bg-white dark:bg-gray-950',
    secondary: 'bg-gray-50 dark:bg-gray-900',
    tertiary: 'bg-gray-100 dark:bg-gray-800',
  },
  border: {
    default: 'border-gray-200 dark:border-gray-800',
    strong: 'border-gray-300 dark:border-gray-700',
  },
  text: {
    primary: 'text-gray-900 dark:text-white',
    secondary: 'text-gray-500 dark:text-gray-400',
    tertiary: 'text-gray-400 dark:text-gray-500',
  },
} as const;

/**
 * Brand Colors
 * Primary brand color for CTAs and interactive elements
 */
export const brandColors = {
  primary: {
    bg: 'bg-primary-600 hover:bg-primary-700',
    text: 'text-primary-600 dark:text-primary-400',
    border: 'border-primary-600 dark:border-primary-400',
    hex: '#2563EB',
  },
} as const;

// ============================================================================
// TYPOGRAPHY
// ============================================================================

/**
 * Type Scale
 * Font sizes for headings, body text, and captions
 */
export const typography = {
  h1: {
    size: 'text-3xl',        // 30px
    weight: 'font-bold',
    lineHeight: 'leading-tight',
  },
  h2: {
    size: 'text-2xl',        // 24px
    weight: 'font-semibold',
    lineHeight: 'leading-tight',
  },
  h3: {
    size: 'text-xl',         // 20px
    weight: 'font-semibold',
    lineHeight: 'leading-snug',
  },
  h4: {
    size: 'text-lg',         // 18px
    weight: 'font-medium',
    lineHeight: 'leading-snug',
  },
  body: {
    size: 'text-base',       // 16px
    weight: 'font-normal',
    lineHeight: 'leading-relaxed',
  },
  caption: {
    size: 'text-sm',         // 14px
    weight: 'font-normal',
    lineHeight: 'leading-normal',
  },
  small: {
    size: 'text-xs',         // 12px
    weight: 'font-normal',
    lineHeight: 'leading-normal',
  },
} as const;

// ============================================================================
// SPACING
// ============================================================================

/**
 * Spacing Scale
 * Consistent spacing values for margins, padding, and gaps
 */
export const spacing = {
  xs: '4px',    // 0.25rem
  sm: '8px',    // 0.5rem
  md: '12px',   // 0.75rem
  lg: '16px',   // 1rem
  xl: '24px',   // 1.5rem
  '2xl': '32px', // 2rem
  '3xl': '48px', // 3rem
  '4xl': '64px', // 4rem
} as const;

/**
 * Spacing Classes
 * Tailwind classes for consistent spacing
 */
export const spacingClasses = {
  xs: 'p-1',      // 4px
  sm: 'p-2',      // 8px
  md: 'p-3',      // 12px
  lg: 'p-4',      // 16px
  xl: 'p-6',      // 24px
  '2xl': 'p-8',   // 32px
  '3xl': 'p-12',  // 48px
  '4xl': 'p-16',  // 64px
} as const;

// ============================================================================
// SHADOWS
// ============================================================================

/**
 * Shadow Scale
 * Elevation levels for cards, modals, and dropdowns
 */
export const shadows = {
  none: 'shadow-none',
  subtle: 'shadow-sm',      // 0 1px 2px rgba(0,0,0,0.05)
  medium: 'shadow-md',      // 0 4px 6px rgba(0,0,0,0.1)
  large: 'shadow-lg',       // 0 10px 15px rgba(0,0,0,0.1)
  xl: 'shadow-xl',          // 0 20px 25px rgba(0,0,0,0.1)
} as const;

// ============================================================================
// BORDER RADIUS
// ============================================================================

/**
 * Border Radius Scale
 * Consistent rounding for buttons, cards, and inputs
 */
export const borderRadius = {
  none: 'rounded-none',
  sm: 'rounded-sm',         // 2px
  default: 'rounded',       // 4px
  md: 'rounded-md',         // 6px
  lg: 'rounded-lg',         // 8px
  xl: 'rounded-xl',         // 12px
  '2xl': 'rounded-2xl',     // 16px
  full: 'rounded-full',     // 9999px
} as const;

// ============================================================================
// Z-INDEX
// ============================================================================

/**
 * Z-Index Scale
 * Layering system for overlays, modals, and dropdowns
 */
export const zIndex = {
  base: 0,
  dropdown: 10,
  sticky: 20,
  overlay: 30,
  modal: 40,
  popover: 50,
  tooltip: 60,
} as const;

// ============================================================================
// COMPONENT SIZES
// ============================================================================

/**
 * Button Sizes
 */
export const buttonSizes = {
  sm: {
    padding: 'px-3 py-1.5',
    text: 'text-sm',
    height: 'h-8',
  },
  md: {
    padding: 'px-4 py-2',
    text: 'text-base',
    height: 'h-10',
  },
  lg: {
    padding: 'px-6 py-3',
    text: 'text-lg',
    height: 'h-12',
  },
} as const;

/**
 * Badge Sizes
 */
export const badgeSizes = {
  sm: {
    padding: 'px-2 py-0.5',
    text: 'text-xs',
  },
  md: {
    padding: 'px-2.5 py-1',
    text: 'text-sm',
  },
  lg: {
    padding: 'px-3 py-1.5',
    text: 'text-base',
  },
} as const;

/**
 * Input Sizes
 */
export const inputSizes = {
  sm: {
    padding: 'px-3 py-1.5',
    text: 'text-sm',
    height: 'h-8',
  },
  md: {
    padding: 'px-4 py-2',
    text: 'text-base',
    height: 'h-10',
  },
  lg: {
    padding: 'px-4 py-3',
    text: 'text-lg',
    height: 'h-12',
  },
} as const;

// ============================================================================
// TRANSITIONS
// ============================================================================

/**
 * Transition Durations
 */
export const transitions = {
  fast: 'duration-150',
  normal: 'duration-200',
  slow: 'duration-300',
  ease: 'ease-in-out',
} as const;

// ============================================================================
// BREAKPOINTS
// ============================================================================

/**
 * Responsive Breakpoints
 * Matches Tailwind's default breakpoints
 */
export const breakpoints = {
  sm: '640px',
  md: '768px',
  lg: '1024px',
  xl: '1280px',
  '2xl': '1536px',
} as const;

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/**
 * Get severity color classes
 */
export function getSeverityColor(severity: 'critical' | 'high' | 'medium' | 'low' | 'info') {
  return severityColors[severity];
}

/**
 * Get status color classes
 */
export function getStatusColor(status: 'healthy' | 'warning' | 'degraded' | 'critical') {
  return statusColors[status];
}

/**
 * Combine Tailwind classes safely (removes duplicates)
 */
export function cn(...classes: (string | undefined | null | false)[]): string {
  return classes.filter(Boolean).join(' ');
}

// ============================================================================
// TYPE EXPORTS
// ============================================================================

export type SeverityLevel = keyof typeof severityColors;
export type StatusLevel = keyof typeof statusColors;
export type SpacingSize = keyof typeof spacing;
export type ShadowSize = keyof typeof shadows;
export type ButtonSize = keyof typeof buttonSizes;
export type BadgeSize = keyof typeof badgeSizes;
export type InputSize = keyof typeof inputSizes;
