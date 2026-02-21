'use client';

import React, { ReactNode } from 'react';
import { cn } from '@/lib/utils';
import { LucideIcon, ChevronDown, Lock } from 'lucide-react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';

// ============================================================================
// Types
// ============================================================================

export interface NavigationItem {
  name: string;
  href: string;
  icon?: LucideIcon;
  badge?: ReactNode;
  current?: boolean;
  /** Feature string required to access this item (e.g. "code_quality") */
  requiredFeature?: string;
  /** Label shown on the lock badge (e.g. "Pro", "Enterprise") */
  tierLabel?: string;
}

export interface NavigationSection {
  id: string;
  label: string;
  icon?: LucideIcon;
  color?: string;
  items: NavigationItem[];
  collapsible?: boolean;
  defaultCollapsed?: boolean;
}

export interface NavigationProps {
  sections: NavigationSection[];
  className?: string;
  onItemClick?: (item: NavigationItem) => void;
  /** Features enabled on the current license — used to show/hide lock badges */
  enabledFeatures?: string[];
}

export interface NavigationItemProps {
  item: NavigationItem;
  onClick?: () => void;
  className?: string;
  locked?: boolean;
}

export interface NavigationSectionHeaderProps {
  section: NavigationSection;
  collapsed?: boolean;
  onToggle?: () => void;
}

// ============================================================================
// NavigationItem Component
// ============================================================================

export function NavigationItemComponent({
  item,
  onClick,
  className,
  locked = false,
}: NavigationItemProps) {
  const pathname = usePathname();
  const isActive = pathname === item.href || item.current;

  const content = (
    <>
      {item.icon && (
        <item.icon className={cn(
          'h-5 w-5 flex-shrink-0',
          locked ? 'text-gray-300 dark:text-gray-600' : isActive ? 'text-primary-600 dark:text-primary-400' : 'text-gray-400 dark:text-gray-500'
        )} />
      )}
      <span className={cn('flex-1 truncate', locked && 'text-gray-400 dark:text-gray-500')}>
        {item.name}
      </span>
      {locked ? (
        <span className="ml-auto flex items-center gap-1">
          <Lock className="h-3 w-3 text-gray-400 dark:text-gray-500" />
          {item.tierLabel && (
            <span className="text-[10px] font-semibold px-1.5 py-0.5 rounded bg-gray-100 dark:bg-gray-800 text-gray-500 dark:text-gray-400 border border-gray-200 dark:border-gray-700">
              {item.tierLabel}
            </span>
          )}
        </span>
      ) : (
        item.badge && <span className="ml-auto">{item.badge}</span>
      )}
    </>
  );

  const baseClasses = cn(
    'group flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors',
    locked
      ? 'text-gray-400 dark:text-gray-500 cursor-default opacity-70'
      : isActive
      ? 'bg-primary-50 dark:bg-primary-900/20 text-primary-700 dark:text-primary-300'
      : 'text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-800 hover:text-gray-900 dark:hover:text-white',
    className
  );

  if (locked) {
    // Locked items link to settings/license upgrade page
    return (
      <Link href="/settings" className={baseClasses} title={`Requires ${item.tierLabel ?? 'upgrade'} — click to manage license`}>
        {content}
      </Link>
    );
  }

  if (item.href) {
    return (
      <Link href={item.href} className={baseClasses} onClick={onClick}>
        {content}
      </Link>
    );
  }

  return (
    <button className={baseClasses} onClick={onClick}>
      {content}
    </button>
  );
}

// ============================================================================
// NavigationSectionHeader Component
// ============================================================================

export function NavigationSectionHeader({
  section,
  collapsed = false,
  onToggle,
}: NavigationSectionHeaderProps) {
  const SectionIcon = section.icon;

  return (
    <div
      className={cn(
        'flex items-center gap-2 px-3 py-2 mb-2',
        section.collapsible && 'cursor-pointer hover:bg-gray-50 dark:hover:bg-gray-800 rounded-lg transition-colors'
      )}
      onClick={section.collapsible ? onToggle : undefined}
    >
      {SectionIcon && (
        <SectionIcon
          className={cn('h-4 w-4 flex-shrink-0', section.color || 'text-gray-500 dark:text-gray-400')}
        />
      )}
      <span className="text-xs font-semibold uppercase tracking-wider text-gray-500 dark:text-gray-400 flex-1">
        {section.label}
      </span>
      {section.collapsible && (
        <ChevronDown
          className={cn(
            'h-4 w-4 text-gray-400 transition-transform',
            collapsed && '-rotate-90'
          )}
        />
      )}
    </div>
  );
}

// ============================================================================
// Navigation Component
// ============================================================================

export function Navigation({ sections, className, onItemClick, enabledFeatures }: NavigationProps) {
  const [collapsedSections, setCollapsedSections] = React.useState<Set<string>>(
    new Set(sections.filter((s) => s.defaultCollapsed).map((s) => s.id))
  );

  const toggleSection = (sectionId: string) => {
    setCollapsedSections((prev) => {
      const next = new Set(prev);
      if (next.has(sectionId)) {
        next.delete(sectionId);
      } else {
        next.add(sectionId);
      }
      return next;
    });
  };

  return (
    <nav className={cn('space-y-6', className)}>
      {sections.map((section) => {
        const isCollapsed = collapsedSections.has(section.id);

        return (
          <div key={section.id}>
            <NavigationSectionHeader
              section={section}
              collapsed={isCollapsed}
              onToggle={() => section.collapsible && toggleSection(section.id)}
            />
            {!isCollapsed && (
              <div className="space-y-1">
                {section.items.map((item) => {
                  const isLocked =
                    !!item.requiredFeature &&
                    !!enabledFeatures &&
                    !enabledFeatures.includes(item.requiredFeature);
                  return (
                    <NavigationItemComponent
                      key={item.href || item.name}
                      item={item}
                      onClick={isLocked ? undefined : () => onItemClick?.(item)}
                      locked={isLocked}
                    />
                  );
                })}
              </div>
            )}
          </div>
        );
      })}
    </nav>
  );
}

// Export compound components
Navigation.Item = NavigationItemComponent;
Navigation.SectionHeader = NavigationSectionHeader;
