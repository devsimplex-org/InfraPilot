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

// ============================================================================
// LogoSpinner Component (Animated logo loader)
// ============================================================================

export interface LogoSpinnerProps {
  size?: 'sm' | 'md' | 'lg' | 'xl';
  label?: string;
  className?: string;
}

const logoSizeClasses = {
  sm: 'w-12 h-12',
  md: 'w-16 h-16',
  lg: 'w-24 h-24',
  xl: 'w-32 h-32',
};

export function LogoSpinner({ size = 'lg', label, className }: LogoSpinnerProps) {
  return (
    <div className={cn("flex flex-col items-center gap-3", className)}>
      <svg
        xmlns="http://www.w3.org/2000/svg"
        viewBox="0 0 400 400"
        className={cn(logoSizeClasses[size])}
      >
        <defs>
          <linearGradient id="gradient1" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" style={{ stopColor: '#3b82f6', stopOpacity: 1 }} />
            <stop offset="100%" style={{ stopColor: '#2563eb', stopOpacity: 1 }} />
          </linearGradient>
          <linearGradient id="gradient2" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" style={{ stopColor: '#60a5fa', stopOpacity: 1 }} />
            <stop offset="100%" style={{ stopColor: '#3b82f6', stopOpacity: 1 }} />
          </linearGradient>
        </defs>

        {/* Outer Container Frame */}
        <rect x="50" y="80" width="300" height="240" rx="12" fill="none" stroke="url(#gradient1)" strokeWidth="4"/>

        {/* Inner Container Layers - Animated pulse */}
        <rect x="70" y="100" width="260" height="60" rx="6" fill="url(#gradient2)" className="animate-pulse" style={{ animationDelay: '0ms' }} opacity="0.3"/>
        <rect x="70" y="170" width="260" height="60" rx="6" fill="url(#gradient2)" className="animate-pulse" style={{ animationDelay: '150ms' }} opacity="0.5"/>
        <rect x="70" y="240" width="260" height="60" rx="6" fill="url(#gradient2)" className="animate-pulse" style={{ animationDelay: '300ms' }} opacity="0.7"/>

        {/* Cockpit Dashboard Elements - Blinking */}
        <circle cx="110" cy="130" r="12" fill="#60a5fa" className="animate-pulse" style={{ animationDelay: '0ms' }} opacity="0.8"/>
        <circle cx="140" cy="130" r="12" fill="#60a5fa" className="animate-pulse" style={{ animationDelay: '200ms' }} opacity="0.8"/>
        <circle cx="170" cy="130" r="12" fill="#60a5fa" className="animate-pulse" style={{ animationDelay: '400ms' }} opacity="0.8"/>

        {/* Monitoring Lines - Animated width */}
        <line x1="220" y1="120" x2="310" y2="120" stroke="#3b82f6" strokeWidth="3" strokeLinecap="round" className="animate-pulse"/>
        <line x1="220" y1="135" x2="290" y2="135" stroke="#60a5fa" strokeWidth="3" strokeLinecap="round" className="animate-pulse" style={{ animationDelay: '100ms' }}/>

        <line x1="90" y1="195" x2="310" y2="195" stroke="#3b82f6" strokeWidth="3" strokeLinecap="round" className="animate-pulse" style={{ animationDelay: '200ms' }}/>
        <line x1="90" y1="210" x2="270" y2="210" stroke="#60a5fa" strokeWidth="3" strokeLinecap="round" className="animate-pulse" style={{ animationDelay: '300ms' }}/>

        {/* Control Panel Icon */}
        <rect x="90" y="255" width="40" height="30" rx="4" fill="#2563eb" className="animate-pulse" style={{ animationDelay: '0ms' }} opacity="0.9"/>
        <rect x="145" y="255" width="40" height="30" rx="4" fill="#2563eb" className="animate-pulse" style={{ animationDelay: '150ms' }} opacity="0.9"/>
        <rect x="200" y="255" width="40" height="30" rx="4" fill="#2563eb" className="animate-pulse" style={{ animationDelay: '300ms' }} opacity="0.9"/>

        {/* Navigation Arrow - Bounce animation */}
        <path d="M 200 20 L 230 60 L 215 60 L 215 80 L 185 80 L 185 60 L 170 60 Z" fill="url(#gradient1)" className="animate-bounce" style={{ transformOrigin: 'center' }}/>

        {/* Status Indicators - Alternating blink */}
        <circle cx="280" cy="270" r="8" fill="#10b981" className="animate-ping" style={{ animationDuration: '1.5s' }} opacity="0.9"/>
        <circle cx="280" cy="270" r="8" fill="#10b981" opacity="0.9"/>
        <circle cx="305" cy="270" r="8" fill="#3b82f6" className="animate-ping" style={{ animationDuration: '1.5s', animationDelay: '750ms' }} opacity="0.9"/>
        <circle cx="305" cy="270" r="8" fill="#3b82f6" opacity="0.9"/>
      </svg>
      {label && (
        <p className="text-sm text-gray-500 dark:text-gray-400 animate-pulse">{label}</p>
      )}
    </div>
  );
}

// ============================================================================
// LogoPageSpinner Component (Full page with logo)
// ============================================================================

export interface LogoPageSpinnerProps {
  label?: string;
}

export function LogoPageSpinner({ label = 'Loading...' }: LogoPageSpinnerProps) {
  return (
    <div className="flex items-center justify-center min-h-[400px]">
      <LogoSpinner size="xl" label={label} />
    </div>
  );
}

// Export compound components
Spinner.Page = PageSpinner;
Spinner.Overlay = OverlaySpinner;
Spinner.Logo = LogoSpinner;
Spinner.LogoPage = LogoPageSpinner;
