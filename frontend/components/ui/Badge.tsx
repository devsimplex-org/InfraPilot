import React from 'react';
import { cn, type SeverityLevel, type StatusLevel, getSeverityColor, getStatusColor } from '@/lib/design-tokens';
import { LucideIcon } from 'lucide-react';

export type BadgeVariant = 'default' | 'severity' | 'status';
export type BadgeSize = 'sm' | 'md' | 'lg';
export type BadgeColor = 'gray' | 'red' | 'yellow' | 'green' | 'blue' | 'purple' | 'orange';

export interface BadgeProps {
  /**
   * The variant determines the color scheme
   */
  variant?: BadgeVariant;

  /**
   * Severity level (when variant="severity")
   */
  severity?: SeverityLevel;

  /**
   * Status level (when variant="status")
   */
  status?: StatusLevel;

  /**
   * Direct color specification (legacy support)
   */
  color?: BadgeColor;

  /**
   * Badge size
   */
  size?: BadgeSize;

  /**
   * Optional icon to display before the text
   */
  icon?: LucideIcon;

  /**
   * Badge content
   */
  children: React.ReactNode;

  /**
   * Additional CSS classes
   */
  className?: string;
}

const sizeClasses = {
  sm: 'px-2 py-0.5 text-xs',
  md: 'px-2.5 py-1 text-sm',
  lg: 'px-3 py-1.5 text-base',
};

const iconSizes = {
  sm: 'h-3 w-3',
  md: 'h-4 w-4',
  lg: 'h-5 w-5',
};

const colorClasses: Record<BadgeColor, string> = {
  gray: 'bg-gray-100 text-gray-700 border-gray-200 dark:bg-gray-800 dark:text-gray-300 dark:border-gray-700',
  red: 'bg-red-100 text-red-700 border-red-200 dark:bg-red-900/30 dark:text-red-400 dark:border-red-800',
  yellow: 'bg-yellow-100 text-yellow-700 border-yellow-200 dark:bg-yellow-900/30 dark:text-yellow-400 dark:border-yellow-800',
  green: 'bg-green-100 text-green-700 border-green-200 dark:bg-green-900/30 dark:text-green-400 dark:border-green-800',
  blue: 'bg-blue-100 text-blue-700 border-blue-200 dark:bg-blue-900/30 dark:text-blue-400 dark:border-blue-800',
  purple: 'bg-purple-100 text-purple-700 border-purple-200 dark:bg-purple-900/30 dark:text-purple-400 dark:border-purple-800',
  orange: 'bg-orange-100 text-orange-700 border-orange-200 dark:bg-orange-900/30 dark:text-orange-400 dark:border-orange-800',
};

export function Badge({
  variant = 'default',
  severity,
  status,
  color,
  size = 'md',
  icon: Icon,
  children,
  className,
}: BadgeProps) {
  // Determine color classes based on variant or color prop
  let badgeColorClasses = '';

  if (color) {
    // Direct color specification takes precedence
    badgeColorClasses = colorClasses[color];
  } else if (variant === 'severity' && severity) {
    const colors = getSeverityColor(severity);
    badgeColorClasses = `${colors.bg} ${colors.text} ${colors.border}`;
  } else if (variant === 'status' && status) {
    const colors = getStatusColor(status);
    badgeColorClasses = `${colors.bg} ${colors.text} ${colors.border}`;
  } else {
    // Default variant
    badgeColorClasses = colorClasses.gray;
  }

  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 rounded-md font-medium border',
        sizeClasses[size],
        badgeColorClasses,
        className
      )}
    >
      {Icon && <Icon className={iconSizes[size]} />}
      {children}
    </span>
  );
}

/**
 * Specialized badge for displaying severity levels
 */
export function SeverityBadge({
  severity,
  size = 'md',
  icon,
  className,
}: {
  severity: SeverityLevel;
  size?: BadgeSize;
  icon?: LucideIcon;
  className?: string;
}) {
  return (
    <Badge
      variant="severity"
      severity={severity}
      size={size}
      icon={icon}
      className={className}
    >
      {severity.toUpperCase()}
    </Badge>
  );
}

/**
 * Specialized badge for displaying status levels
 */
export function StatusBadge({
  status,
  size = 'md',
  icon,
  className,
  children,
}: {
  status: StatusLevel;
  size?: BadgeSize;
  icon?: LucideIcon;
  className?: string;
  children?: React.ReactNode;
}) {
  return (
    <Badge
      variant="status"
      status={status}
      size={size}
      icon={icon}
      className={className}
    >
      {children || status.charAt(0).toUpperCase() + status.slice(1)}
    </Badge>
  );
}
