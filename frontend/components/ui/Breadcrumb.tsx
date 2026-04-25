import React, { ReactNode } from 'react';
import { cn } from '@/lib/utils';
import { ChevronRight, Home } from 'lucide-react';
import Link from 'next/link';

// ============================================================================
// Types
// ============================================================================

export interface BreadcrumbItem {
  label: string;
  href?: string;
  current?: boolean;
}

export interface BreadcrumbProps {
  items: BreadcrumbItem[];
  showHome?: boolean;
  separator?: ReactNode;
  className?: string;
}

// ============================================================================
// Breadcrumb Component
// ============================================================================

export function Breadcrumb({
  items,
  showHome = true,
  separator = <ChevronRight className="h-4 w-4" />,
  className,
}: BreadcrumbProps) {
  const allItems = showHome
    ? [{ label: 'Home', href: '/' }, ...items]
    : items;

  return (
    <nav aria-label="Breadcrumb" className={cn('flex items-center gap-2', className)}>
      <ol className="flex items-center gap-2">
        {allItems.map((item, index) => {
          const isLast = index === allItems.length - 1;
          const isHome = showHome && index === 0;

          return (
            <li key={index} className="flex items-center gap-2">
              {index > 0 && (
                <span className="text-gray-400 dark:text-gray-600">{separator}</span>
              )}

              {isLast || !item.href ? (
                <span
                  className={cn(
                    'text-sm font-medium',
                    isLast
                      ? 'text-gray-900 dark:text-white'
                      : 'text-gray-500 dark:text-gray-400'
                  )}
                  aria-current={isLast ? 'page' : undefined}
                >
                  {isHome ? <Home className="h-4 w-4" /> : item.label}
                </span>
              ) : (
                <Link
                  href={item.href}
                  className="text-sm font-medium text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300 transition-colors"
                >
                  {isHome ? <Home className="h-4 w-4" /> : item.label}
                </Link>
              )}
            </li>
          );
        })}
      </ol>
    </nav>
  );
}
