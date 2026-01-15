import React from 'react';
import { cn } from '@/lib/utils';

// ============================================================================
// Types
// ============================================================================

export interface SkeletonProps {
  className?: string;
  variant?: 'text' | 'circular' | 'rectangular';
  width?: string | number;
  height?: string | number;
  animate?: boolean;
}

// ============================================================================
// Skeleton Component
// ============================================================================

export function Skeleton({
  className,
  variant = 'rectangular',
  width,
  height,
  animate = true,
}: SkeletonProps) {
  const variantClasses = {
    text: 'rounded',
    circular: 'rounded-full',
    rectangular: 'rounded-lg',
  };

  const style: React.CSSProperties = {};
  if (width) style.width = typeof width === 'number' ? `${width}px` : width;
  if (height) style.height = typeof height === 'number' ? `${height}px` : height;

  return (
    <div
      className={cn(
        'bg-gray-200 dark:bg-gray-700',
        variantClasses[variant],
        animate && 'animate-pulse',
        className
      )}
      style={style}
    />
  );
}

// ============================================================================
// SkeletonText Component
// ============================================================================

export interface SkeletonTextProps {
  lines?: number;
  className?: string;
  lastLineWidth?: string;
}

export function SkeletonText({
  lines = 3,
  className,
  lastLineWidth = '60%',
}: SkeletonTextProps) {
  return (
    <div className={cn('space-y-3', className)}>
      {Array.from({ length: lines }).map((_, index) => (
        <Skeleton
          key={index}
          variant="text"
          height={16}
          width={index === lines - 1 ? lastLineWidth : '100%'}
        />
      ))}
    </div>
  );
}

// ============================================================================
// SkeletonCard Component
// ============================================================================

export interface SkeletonCardProps {
  className?: string;
  hasImage?: boolean;
}

export function SkeletonCard({ className, hasImage = false }: SkeletonCardProps) {
  return (
    <div
      className={cn(
        'p-6 bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-lg',
        className
      )}
    >
      {hasImage && <Skeleton className="mb-4" height={200} />}
      <Skeleton className="mb-3" height={20} width="70%" />
      <SkeletonText lines={3} lastLineWidth="40%" />
    </div>
  );
}

// ============================================================================
// SkeletonTable Component
// ============================================================================

export interface SkeletonTableProps {
  rows?: number;
  columns?: number;
  className?: string;
}

export function SkeletonTable({
  rows = 5,
  columns = 4,
  className,
}: SkeletonTableProps) {
  return (
    <div className={cn('space-y-3', className)}>
      {/* Header */}
      <div className="flex gap-4 px-6 py-3 bg-gray-50 dark:bg-gray-800 rounded-t-lg">
        {Array.from({ length: columns }).map((_, index) => (
          <Skeleton key={index} height={16} width="100%" className="flex-1" />
        ))}
      </div>
      {/* Rows */}
      {Array.from({ length: rows }).map((_, rowIndex) => (
        <div key={rowIndex} className="flex gap-4 px-6 py-3">
          {Array.from({ length: columns }).map((_, colIndex) => (
            <Skeleton key={colIndex} height={16} width="100%" className="flex-1" />
          ))}
        </div>
      ))}
    </div>
  );
}

// Export compound components
Skeleton.Text = SkeletonText;
Skeleton.Card = SkeletonCard;
Skeleton.Table = SkeletonTable;
