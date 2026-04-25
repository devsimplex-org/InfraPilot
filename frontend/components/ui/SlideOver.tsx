'use client';

import React, { ReactNode, useEffect, Fragment } from 'react';
import { cn } from '@/lib/utils';
import { X } from 'lucide-react';
import { Dialog, Transition } from '@headlessui/react';

// ============================================================================
// Types
// ============================================================================

export interface SlideOverProps {
  isOpen: boolean;
  onClose: () => void;
  children: ReactNode;
  size?: 'sm' | 'md' | 'lg' | 'xl' | 'full';
  className?: string;
  /**
   * Optional title - if provided, automatically renders a header
   */
  title?: string;
}

export interface SlideOverHeaderProps {
  children: ReactNode;
  className?: string;
  onClose?: () => void;
  showCloseButton?: boolean;
}

export interface SlideOverBodyProps {
  children: ReactNode;
  className?: string;
  noPadding?: boolean;
}

export interface SlideOverFooterProps {
  children: ReactNode;
  className?: string;
  align?: 'left' | 'center' | 'right' | 'between';
}

// ============================================================================
// Size configurations
// ============================================================================

const sizeClasses = {
  sm: 'max-w-md',
  md: 'max-w-lg',
  lg: 'max-w-2xl',
  xl: 'max-w-4xl',
  full: 'max-w-full',
};

// ============================================================================
// SlideOverHeader Component
// ============================================================================

export function SlideOverHeader({
  children,
  className,
  onClose,
  showCloseButton = true,
}: SlideOverHeaderProps) {
  return (
    <div
      className={cn(
        'flex items-center justify-between px-6 py-4 border-b border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900',
        className
      )}
    >
      <div className="flex-1">{children}</div>
      {showCloseButton && onClose && (
        <button
          type="button"
          onClick={onClose}
          className="ml-4 rounded-md text-gray-400 hover:text-gray-500 dark:hover:text-gray-300 focus:outline-none focus:ring-2 focus:ring-primary-500"
        >
          <span className="sr-only">Close</span>
          <X className="h-6 w-6" />
        </button>
      )}
    </div>
  );
}

// ============================================================================
// SlideOverBody Component
// ============================================================================

export function SlideOverBody({
  children,
  className,
  noPadding = false,
}: SlideOverBodyProps) {
  return (
    <div
      className={cn(
        'flex-1 overflow-y-auto bg-white dark:bg-gray-900',
        !noPadding && 'px-6 py-6',
        className
      )}
    >
      {children}
    </div>
  );
}

// ============================================================================
// SlideOverFooter Component
// ============================================================================

export function SlideOverFooter({
  children,
  className,
  align = 'right',
}: SlideOverFooterProps) {
  const alignClasses = {
    left: 'justify-start',
    center: 'justify-center',
    right: 'justify-end',
    between: 'justify-between',
  };

  return (
    <div
      className={cn(
        'flex items-center gap-3 px-6 py-4 border-t border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800/50',
        alignClasses[align],
        className
      )}
    >
      {children}
    </div>
  );
}

// ============================================================================
// SlideOver Component (Main)
// ============================================================================

export function SlideOver({
  isOpen,
  onClose,
  children,
  size = 'md',
  className,
  title,
}: SlideOverProps) {
  // Prevent body scroll when SlideOver is open
  useEffect(() => {
    if (isOpen) {
      document.body.style.overflow = 'hidden';
    } else {
      document.body.style.overflow = '';
    }

    return () => {
      document.body.style.overflow = '';
    };
  }, [isOpen]);

  return (
    <Transition.Root show={isOpen} as={Fragment}>
      <Dialog as="div" className="relative z-50" onClose={onClose}>
        {/* Backdrop */}
        <Transition.Child
          as={Fragment}
          enter="ease-in-out duration-300"
          enterFrom="opacity-0"
          enterTo="opacity-100"
          leave="ease-in-out duration-300"
          leaveFrom="opacity-100"
          leaveTo="opacity-0"
        >
          <div className="fixed inset-0 bg-gray-900/50 dark:bg-gray-950/80 backdrop-blur-sm transition-opacity" />
        </Transition.Child>

        {/* SlideOver Panel */}
        <div className="fixed inset-0 overflow-hidden">
          <div className="absolute inset-0 overflow-hidden">
            <div className="pointer-events-none fixed inset-y-0 right-0 flex max-w-full pl-10">
              <Transition.Child
                as={Fragment}
                enter="transform transition ease-in-out duration-300"
                enterFrom="translate-x-full"
                enterTo="translate-x-0"
                leave="transform transition ease-in-out duration-300"
                leaveFrom="translate-x-0"
                leaveTo="translate-x-full"
              >
                <Dialog.Panel
                  className={cn(
                    'pointer-events-auto w-screen',
                    sizeClasses[size]
                  )}
                >
                  <div
                    className={cn(
                      'flex h-full flex-col shadow-xl bg-white dark:bg-gray-900',
                      className
                    )}
                  >
                    {title && (
                      <SlideOverHeader onClose={onClose}>
                        <h2 className="text-lg font-semibold text-gray-900 dark:text-white">{title}</h2>
                      </SlideOverHeader>
                    )}
                    {title ? <SlideOverBody>{children}</SlideOverBody> : children}
                  </div>
                </Dialog.Panel>
              </Transition.Child>
            </div>
          </div>
        </div>
      </Dialog>
    </Transition.Root>
  );
}

// Export compound components
SlideOver.Header = SlideOverHeader;
SlideOver.Body = SlideOverBody;
SlideOver.Footer = SlideOverFooter;
