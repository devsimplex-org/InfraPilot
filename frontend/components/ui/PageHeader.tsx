import React, { ReactNode } from 'react';
import { cn } from '@/lib/utils';
import { LucideIcon } from 'lucide-react';

// ============================================================================
// Types
// ============================================================================

export interface PageHeaderProps {
  title: string;
  description?: string;
  action?: ReactNode;
  breadcrumbs?: ReactNode;
  icon?: LucideIcon;
  className?: string;
}

// ============================================================================
// PageHeader Component
// ============================================================================

export function PageHeader({
  title,
  description,
  action,
  breadcrumbs,
  icon: Icon,
  className,
}: PageHeaderProps) {
  return (
    <div className={cn('mb-6', className)}>
      {breadcrumbs && <div className="mb-2">{breadcrumbs}</div>}
      <div className="flex items-start justify-between">
        <div className="flex-1">
          <div className="flex items-center gap-3">
            {Icon && <Icon className="h-7 w-7 text-gray-700 dark:text-gray-300" />}
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
              {title}
            </h1>
          </div>
          {description && (
            <p className="mt-2 text-sm text-gray-500 dark:text-gray-400">
              {description}
            </p>
          )}
        </div>
        {action && <div className="ml-4 flex-shrink-0">{action}</div>}
      </div>
    </div>
  );
}
