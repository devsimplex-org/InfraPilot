import React from 'react';
import { LucideIcon, TrendingUp, TrendingDown } from 'lucide-react';
import { Card } from './Card';
import { cn } from '@/lib/design-tokens';

export interface StatCardProps {
  /**
   * The main label for the stat
   */
  label: string;

  /**
   * The value to display (usually a number)
   */
  value: number | string;

  /**
   * Optional description or secondary text
   */
  description?: string;

  /**
   * Icon to display (usually lucide-react icon)
   */
  icon?: LucideIcon;

  /**
   * Trend direction (shows trend indicator)
   */
  trend?: 'up' | 'down' | 'neutral';

  /**
   * Trend value (e.g., "+12% from last week")
   */
  trendValue?: string;

  /**
   * Icon color (overrides default)
   */
  iconColor?: string;

  /**
   * Value color (overrides default)
   */
  valueColor?: string;

  /**
   * Additional CSS classes
   */
  className?: string;

  /**
   * Click handler
   */
  onClick?: () => void;
}

export function StatCard({
  label,
  value,
  description,
  icon: Icon,
  trend,
  trendValue,
  iconColor = 'text-primary-600',
  valueColor = 'text-gray-900 dark:text-white',
  className,
  onClick,
}: StatCardProps) {
  const isClickable = !!onClick;

  return (
    <Card
      variant="default"
      interactive={isClickable}
      onClick={onClick}
      className={className}
    >
      <Card.Body>
        <div className="flex items-center justify-between">
          <div className="flex-1">
            <p className="text-sm text-gray-500 dark:text-gray-400 mb-1">
              {label}
            </p>
            <p className={cn('text-2xl font-bold mt-1', valueColor)}>
              {typeof value === 'number' ? value.toLocaleString() : value}
            </p>
            {description && (
              <p className="text-xs text-gray-500 dark:text-gray-400 mt-2">
                {description}
              </p>
            )}
            {trend && trendValue && (
              <div className="flex items-center gap-1 mt-2">
                {trend === 'up' && (
                  <TrendingUp className="h-4 w-4 text-green-600 dark:text-green-400" />
                )}
                {trend === 'down' && (
                  <TrendingDown className="h-4 w-4 text-red-600 dark:text-red-400" />
                )}
                <span
                  className={cn(
                    'text-xs font-medium',
                    trend === 'up' && 'text-green-600 dark:text-green-400',
                    trend === 'down' && 'text-red-600 dark:text-red-400',
                    trend === 'neutral' && 'text-gray-500 dark:text-gray-400'
                  )}
                >
                  {trendValue}
                </span>
              </div>
            )}
          </div>
          {Icon && (
            <div className={cn('p-3 rounded-lg bg-gray-100 dark:bg-gray-800', iconColor)}>
              <Icon className="h-8 w-8" />
            </div>
          )}
        </div>
      </Card.Body>
    </Card>
  );
}

/**
 * Metrics Grid - Layout component for StatCards
 */
export interface MetricsGridProps {
  children: React.ReactNode;
  className?: string;
  /**
   * Number of columns on desktop (1-6)
   */
  columns?: 1 | 2 | 3 | 4 | 5 | 6;
}

export function MetricsGrid({ children, className, columns = 4 }: MetricsGridProps) {
  const gridColsClass = {
    1: 'lg:grid-cols-1',
    2: 'lg:grid-cols-2',
    3: 'lg:grid-cols-3',
    4: 'lg:grid-cols-4',
    5: 'lg:grid-cols-5',
    6: 'lg:grid-cols-6',
  };

  return (
    <div className={cn('grid grid-cols-1 md:grid-cols-2', gridColsClass[columns], 'gap-4', className)}>
      {children}
    </div>
  );
}
