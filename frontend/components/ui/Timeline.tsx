import React, { ReactNode } from 'react';
import { cn } from '@/lib/utils';
import { LucideIcon } from 'lucide-react';

// ============================================================================
// Types
// ============================================================================

export interface TimelineItemProps {
  icon?: LucideIcon;
  iconColor?: string;
  title: string;
  description?: ReactNode;
  timestamp?: string;
  children?: ReactNode;
  isLast?: boolean;
}

export interface TimelineProps {
  children: ReactNode;
  className?: string;
}

// ============================================================================
// TimelineItem Component
// ============================================================================

export function TimelineItem({
  icon: Icon,
  iconColor = 'text-primary-600 dark:text-primary-400',
  title,
  description,
  timestamp,
  children,
  isLast = false,
}: TimelineItemProps) {
  return (
    <div className="relative pb-8">
      {/* Vertical line */}
      {!isLast && (
        <span
          className="absolute left-4 top-4 -ml-px h-full w-0.5 bg-gray-200 dark:bg-gray-700"
          aria-hidden="true"
        />
      )}

      <div className="relative flex items-start space-x-3">
        {/* Icon */}
        <div className="relative">
          <div
            className={cn(
              'flex h-8 w-8 items-center justify-center rounded-full ring-8 ring-white dark:ring-gray-900 bg-gray-100 dark:bg-gray-800',
              iconColor
            )}
          >
            {Icon ? (
              <Icon className="h-4 w-4" aria-hidden="true" />
            ) : (
              <span className="h-2 w-2 rounded-full bg-current" />
            )}
          </div>
        </div>

        {/* Content */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center justify-between">
            <p className="text-sm font-medium text-gray-900 dark:text-white">
              {title}
            </p>
            {timestamp && (
              <time className="text-xs text-gray-500 dark:text-gray-400 whitespace-nowrap ml-4">
                {timestamp}
              </time>
            )}
          </div>

          {description && (
            <div className="mt-1 text-sm text-gray-600 dark:text-gray-400">
              {description}
            </div>
          )}

          {children && <div className="mt-3">{children}</div>}
        </div>
      </div>
    </div>
  );
}

// ============================================================================
// Timeline Component
// ============================================================================

export function Timeline({ children, className }: TimelineProps) {
  // Add isLast prop to last child
  const childrenArray = React.Children.toArray(children);
  const childrenWithProps = childrenArray.map((child, index) => {
    if (React.isValidElement(child)) {
      return React.cloneElement(child, {
        isLast: index === childrenArray.length - 1,
      } as any);
    }
    return child;
  });

  return (
    <div className={cn('flow-root', className)}>
      <ul className="-mb-8">{childrenWithProps}</ul>
    </div>
  );
}

// Export compound components
Timeline.Item = TimelineItem;
