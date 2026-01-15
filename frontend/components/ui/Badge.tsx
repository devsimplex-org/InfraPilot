import React from 'react';
import { cn, type SeverityLevel, type StatusLevel, getSeverityColor, getStatusColor } from '@/lib/design-tokens';
import { LucideIcon } from 'lucide-react';

export type BadgeVariant = 'default' | 'severity' | 'status';
export type BadgeSize = 'sm' | 'md' | 'lg';

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

export function Badge({
  variant = 'default',
  severity,
  status,
  size = 'md',
  icon: Icon,
  children,
  className,
}: BadgeProps) {
  // Determine color classes based on variant
  let colorClasses = '';

  if (variant === 'severity' && severity) {
    const colors = getSeverityColor(severity);
    colorClasses = `${colors.bg} ${colors.text} ${colors.border}`;
  } else if (variant === 'status' && status) {
    const colors = getStatusColor(status);
    colorClasses = `${colors.bg} ${colors.text} ${colors.border}`;
  } else {
    // Default variant
    colorClasses = 'bg-gray-100 text-gray-700 border-gray-200 dark:bg-gray-800 dark:text-gray-300 dark:border-gray-700';
  }

  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 rounded-md font-medium border',
        sizeClasses[size],
        colorClasses,
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
