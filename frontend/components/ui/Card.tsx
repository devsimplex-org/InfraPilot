import React from 'react';
import { cn } from '@/lib/design-tokens';

export type CardVariant = 'default' | 'elevated' | 'bordered';

export interface CardProps {
  /**
   * Card variant
   */
  variant?: CardVariant;

  /**
   * Card content
   */
  children: React.ReactNode;

  /**
   * Additional CSS classes
   */
  className?: string;

  /**
   * Click handler
   */
  onClick?: () => void;

  /**
   * Whether the card is interactive (adds hover effects)
   */
  interactive?: boolean;
}

const variantClasses: Record<CardVariant, string> = {
  default: 'bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800',
  elevated: 'bg-white dark:bg-gray-900 shadow-md',
  bordered: 'bg-white dark:bg-gray-900 border-2 border-gray-300 dark:border-gray-700',
};

export function Card({
  variant = 'default',
  children,
  className,
  onClick,
  interactive = false,
}: CardProps) {
  const isClickable = !!onClick || interactive;

  return (
    <div
      onClick={onClick}
      className={cn(
        'rounded-lg overflow-hidden',
        variantClasses[variant],
        isClickable && 'cursor-pointer transition-colors hover:bg-gray-50 dark:hover:bg-gray-800/50',
        className
      )}
    >
      {children}
    </div>
  );
}

/**
 * Card Header Component
 */
export interface CardHeaderProps {
  children: React.ReactNode;
  className?: string;
  /**
   * Action button or element to display in the header (right side)
   */
  action?: React.ReactNode;
}

export function CardHeader({ children, className, action }: CardHeaderProps) {
  return (
    <div className={cn('px-6 py-4 border-b border-gray-200 dark:border-gray-800', className)}>
      <div className="flex items-center justify-between">
        <div>{children}</div>
        {action && <div>{action}</div>}
      </div>
    </div>
  );
}

/**
 * Card Body Component
 */
export interface CardBodyProps {
  children: React.ReactNode;
  className?: string;
  /**
   * Reduced padding for compact layouts
   */
  compact?: boolean;
  /**
   * No padding - useful for lists or custom content
   */
  noPadding?: boolean;
}

export function CardBody({ children, className, compact = false, noPadding = false }: CardBodyProps) {
  return (
    <div className={cn(noPadding ? '' : compact ? 'px-6 py-3' : 'px-6 py-4', className)}>
      {children}
    </div>
  );
}

/**
 * Card Footer Component
 */
export interface CardFooterProps {
  children: React.ReactNode;
  className?: string;
}

export function CardFooter({ children, className }: CardFooterProps) {
  return (
    <div className={cn('px-6 py-4 border-t border-gray-200 dark:border-gray-800 bg-gray-50 dark:bg-gray-800/50', className)}>
      {children}
    </div>
  );
}

// Attach sub-components to Card for compound component pattern
Card.Header = CardHeader;
Card.Body = CardBody;
Card.Footer = CardFooter;
