import React from 'react';
import { cn } from '@/lib/utils';
import { Loader2 } from 'lucide-react';

// ============================================================================
// Types
// ============================================================================

export interface SpinnerProps {
  size?: 'sm' | 'md' | 'lg' | 'xl';
  className?: string;
  label?: string;
}

// ============================================================================
// Size configurations
// ============================================================================

const sizeClasses = {
  sm: 'h-4 w-4',
  md: 'h-6 w-6',
  lg: 'h-8 w-8',
  xl: 'h-12 w-12',
};

// ============================================================================
// Spinner Component
// ============================================================================

export function Spinner({ size = 'md', className, label }: SpinnerProps) {
  return (
    <div className="flex flex-col items-center gap-2">
      <Loader2
        className={cn(
          'animate-spin text-primary-600 dark:text-primary-400',
          sizeClasses[size],
          className
        )}
      />
      {label && (
        <p className="text-sm text-gray-500 dark:text-gray-400">{label}</p>
      )}
    </div>
  );
}

// ============================================================================
// PageSpinner Component (Full page loading)
// ============================================================================

export interface PageSpinnerProps {
  label?: string;
}

export function PageSpinner({ label = 'Loading...' }: PageSpinnerProps) {
  return (
    <div className="flex items-center justify-center min-h-screen">
      <Spinner size="xl" label={label} />
    </div>
  );
}

// ============================================================================
// OverlaySpinner Component (Overlay on top of content)
// ============================================================================

export interface OverlaySpinnerProps {
  label?: string;
  visible: boolean;
}

export function OverlaySpinner({
  label = 'Loading...',
  visible,
}: OverlaySpinnerProps) {
  if (!visible) return null;

  return (
    <div className="fixed inset-0 bg-gray-900/50 dark:bg-gray-950/80 backdrop-blur-sm flex items-center justify-center z-50">
      <div className="bg-white dark:bg-gray-900 rounded-lg p-6 shadow-xl">
        <Spinner size="lg" label={label} />
      </div>
    </div>
  );
}

// Export compound components
Spinner.Page = PageSpinner;
Spinner.Overlay = OverlaySpinner;
