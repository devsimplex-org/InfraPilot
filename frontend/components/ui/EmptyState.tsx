import React, { ReactNode } from 'react';
import { cn } from '@/lib/utils';
import { LucideIcon } from 'lucide-react';

// ============================================================================
// Types
// ============================================================================

export interface EmptyStateProps {
  icon?: LucideIcon;
  title: string;
  description?: string;
  action?: ReactNode;
  className?: string;
  iconClassName?: string;
  size?: 'sm' | 'md' | 'lg';
}

// ============================================================================
// Size configurations
// ============================================================================

const sizeConfig = {
  sm: {
    container: 'py-8',
    icon: 'h-8 w-8',
    title: 'text-base',
    description: 'text-sm',
  },
  md: {
    container: 'py-12',
    icon: 'h-12 w-12',
    title: 'text-lg',
    description: 'text-sm',
  },
  lg: {
    container: 'py-16',
    icon: 'h-16 w-16',
    title: 'text-xl',
    description: 'text-base',
  },
};

// ============================================================================
// EmptyState Component
// ============================================================================

export function EmptyState({
  icon: Icon,
  title,
  description,
  action,
  className,
  iconClassName,
  size = 'md',
}: EmptyStateProps) {
  const config = sizeConfig[size];

  return (
    <div className={cn('text-center', config.container, className)}>
      {Icon && (
        <Icon
          className={cn(
            config.icon,
            'mx-auto text-gray-400 dark:text-gray-500 mb-4',
            iconClassName
          )}
        />
      )}
      <h3
        className={cn(
          config.title,
          'font-semibold text-gray-900 dark:text-white mb-2'
        )}
      >
        {title}
      </h3>
      {description && (
        <p
          className={cn(
            config.description,
            'text-gray-500 dark:text-gray-400 max-w-sm mx-auto mb-6'
          )}
        >
          {description}
        </p>
      )}
      {action && <div className="flex justify-center">{action}</div>}
    </div>
  );
}
