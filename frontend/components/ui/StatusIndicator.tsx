import React from 'react';
import { cn } from '@/lib/utils';
import { getStatusColor, StatusLevel } from '@/lib/design-tokens';

// ============================================================================
// Types
// ============================================================================

export interface StatusIndicatorProps {
  status: StatusLevel;
  label?: string;
  pulse?: boolean;
  size?: 'sm' | 'md' | 'lg';
  showLabel?: boolean;
  className?: string;
}

// ============================================================================
// Size configurations
// ============================================================================

const sizeClasses = {
  sm: {
    dot: 'h-2 w-2',
    text: 'text-xs',
    gap: 'gap-1.5',
  },
  md: {
    dot: 'h-3 w-3',
    text: 'text-sm',
    gap: 'gap-2',
  },
  lg: {
    dot: 'h-4 w-4',
    text: 'text-base',
    gap: 'gap-2.5',
  },
};

// ============================================================================
// StatusIndicator Component
// ============================================================================

export function StatusIndicator({
  status,
  label,
  pulse = false,
  size = 'md',
  showLabel = true,
  className,
}: StatusIndicatorProps) {
  const colors = getStatusColor(status);
  const sizeConfig = sizeClasses[size];

  // Get background color for the dot
  const dotColorClass = colors.hex.text.replace('#', '');

  const statusLabels = {
    healthy: 'Healthy',
    warning: 'Warning',
    degraded: 'Degraded',
    critical: 'Critical',
  };

  const displayLabel = label || statusLabels[status];

  return (
    <div className={cn('inline-flex items-center', sizeConfig.gap, className)}>
      <span className="relative flex">
        <span
          className={cn(
            'rounded-full',
            sizeConfig.dot,
            colors.bg.split(' ')[0], // Use only the light mode bg color
          )}
          style={{
            backgroundColor: colors.hex.text,
          }}
        />
        {pulse && (
          <span
            className={cn(
              'absolute inline-flex rounded-full opacity-75 animate-ping',
              sizeConfig.dot,
            )}
            style={{
              backgroundColor: colors.hex.text,
            }}
          />
        )}
      </span>
      {showLabel && (
        <span className={cn('font-medium', colors.text, sizeConfig.text)}>
          {displayLabel}
        </span>
      )}
    </div>
  );
}
