'use client';

import React, { Fragment, useState, useEffect } from 'react';
import { Dialog, Transition } from '@headlessui/react';
import { AlertTriangle, Trash2, RotateCcw, X, Square, Mail, Lock, Eye, EyeOff } from 'lucide-react';
import { cn } from '@/lib/utils';

export type ConfirmLevel = 'simple' | 'name' | 'password' | 'otp';

export interface ConfirmDialogProps {
  isOpen: boolean;
  onClose: () => void;
  onConfirm: () => void;
  title: string;
  message: string;
  confirmText?: string;
  cancelText?: string;
  variant?: 'danger' | 'warning' | 'default';
  icon?: 'delete' | 'redeploy' | 'warning' | 'stop' | 'none';
  isLoading?: boolean;
  /** Confirmation level - determines what verification is required */
  confirmLevel?: ConfirmLevel;
  /** For 'name' level - the value that must be typed to confirm */
  confirmValue?: string;
  /** Placeholder for the confirmation input */
  confirmInputPlaceholder?: string;
  /** Label showing what needs to be entered */
  confirmInputLabel?: string;
  /** Additional content to render (e.g., checkboxes) */
  children?: React.ReactNode;
  /** Error message to display */
  error?: string | null;
  /** Callback when the confirmation input value changes (for syncing with parent state) */
  onInputChange?: (value: string) => void;
  /** For 'password' and 'otp' levels - async validation function */
  onValidate?: (value: string) => Promise<{ valid: boolean; error?: string }>;
  /** For 'otp' level - trigger sending OTP, returns success status */
  onSendOtp?: () => Promise<{ success: boolean; error?: string }>;
}

const iconMap = {
  delete: Trash2,
  redeploy: RotateCcw,
  warning: AlertTriangle,
  stop: Square,
  none: null,
};

const variantStyles = {
  danger: {
    iconBg: 'bg-red-100 dark:bg-red-900/30',
    iconColor: 'text-red-600 dark:text-red-400',
    buttonBg: 'bg-red-600 hover:bg-red-700 dark:bg-red-600 dark:hover:bg-red-700',
    buttonText: 'text-white',
  },
  warning: {
    iconBg: 'bg-yellow-100 dark:bg-yellow-900/30',
    iconColor: 'text-yellow-600 dark:text-yellow-400',
    buttonBg: 'bg-yellow-600 hover:bg-yellow-700 dark:bg-yellow-600 dark:hover:bg-yellow-700',
    buttonText: 'text-white',
  },
  default: {
    iconBg: 'bg-primary-100 dark:bg-primary-900/30',
    iconColor: 'text-primary-600 dark:text-primary-400',
    buttonBg: 'bg-primary-600 hover:bg-primary-700 dark:bg-primary-600 dark:hover:bg-primary-700',
    buttonText: 'text-white',
  },
};

export function ConfirmDialog({
  isOpen,
  onClose,
  onConfirm,
  title,
  message,
  confirmText = 'Confirm',
  cancelText = 'Cancel',
  variant = 'default',
  icon = 'warning',
  isLoading = false,
  confirmLevel = 'simple',
  confirmValue,
  confirmInputPlaceholder,
  confirmInputLabel,
  children,
  error: externalError,
  onInputChange,
  onValidate,
  onSendOtp,
}: ConfirmDialogProps) {
  const [inputValue, setInputValue] = useState('');
  const [internalError, setInternalError] = useState<string | null>(null);
  const [isValidating, setIsValidating] = useState(false);
  const [isSendingOtp, setIsSendingOtp] = useState(false);
  const [otpSent, setOtpSent] = useState(false);
  const [showPassword, setShowPassword] = useState(false);

  const error = externalError || internalError;
  const styles = variantStyles[variant];
  const IconComponent = icon !== 'none' ? iconMap[icon] : null;

  // Reset state when dialog closes
  useEffect(() => {
    if (!isOpen) {
      setInputValue('');
      setInternalError(null);
      setIsValidating(false);
      setIsSendingOtp(false);
      setOtpSent(false);
      setShowPassword(false);
    }
  }, [isOpen]);

  const handleInputChange = (value: string) => {
    setInputValue(value);
    setInternalError(null);
    onInputChange?.(value);
  };

  // Determine if confirm button should be disabled
  const getConfirmDisabled = () => {
    if (isLoading || isValidating) return true;

    switch (confirmLevel) {
      case 'simple':
        return false;
      case 'name':
        return confirmValue ? inputValue !== confirmValue : false;
      case 'password':
        return inputValue.length === 0;
      case 'otp':
        return !otpSent || inputValue.length === 0;
      default:
        return false;
    }
  };

  const handleSendOtp = async () => {
    if (!onSendOtp || isSendingOtp) return;

    setIsSendingOtp(true);
    setInternalError(null);

    try {
      const result = await onSendOtp();
      if (result.success) {
        setOtpSent(true);
      } else {
        setInternalError(result.error || 'Failed to send OTP');
      }
    } catch (err) {
      setInternalError('Failed to send OTP');
    } finally {
      setIsSendingOtp(false);
    }
  };

  const handleConfirm = async () => {
    if (getConfirmDisabled()) return;

    // For password and OTP levels, validate first
    if ((confirmLevel === 'password' || confirmLevel === 'otp') && onValidate) {
      setIsValidating(true);
      setInternalError(null);

      try {
        const result = await onValidate(inputValue);
        if (!result.valid) {
          setInternalError(result.error || 'Validation failed');
          setIsValidating(false);
          return;
        }
      } catch (err) {
        setInternalError('Validation failed');
        setIsValidating(false);
        return;
      }

      setIsValidating(false);
    }

    onConfirm();
    if (!isLoading) {
      onClose();
    }
  };

  // Get placeholder text based on level
  const getPlaceholder = () => {
    if (confirmInputPlaceholder) return confirmInputPlaceholder;
    switch (confirmLevel) {
      case 'name':
        return 'Type to confirm';
      case 'password':
        return 'Enter your password';
      case 'otp':
        return 'Enter OTP code';
      default:
        return '';
    }
  };

  // Get label based on level
  const getLabel = () => {
    if (confirmInputLabel) return confirmInputLabel;
    switch (confirmLevel) {
      case 'name':
        return 'To confirm, type the name shown below:';
      case 'password':
        return 'Enter your password to confirm this action:';
      case 'otp':
        return otpSent
          ? 'Enter the verification code sent to your email:'
          : 'We will send a verification code to your email.';
      default:
        return '';
    }
  };

  const renderConfirmationInput = () => {
    if (confirmLevel === 'simple') return null;

    return (
      <div className="mt-4">
        <p className="text-sm text-gray-600 dark:text-gray-400 mb-2">
          {getLabel()}
        </p>

        {/* Name confirmation - show the value to type */}
        {confirmLevel === 'name' && confirmValue && (
          <div className="p-3 bg-gray-100 dark:bg-gray-800 rounded-lg mb-3">
            <code className="text-sm text-gray-900 dark:text-white font-mono">{confirmValue}</code>
          </div>
        )}

        {/* OTP - show send button if not sent yet */}
        {confirmLevel === 'otp' && !otpSent && (
          <button
            type="button"
            onClick={handleSendOtp}
            disabled={isSendingOtp}
            className="w-full mb-3 px-4 py-2 bg-primary-600 hover:bg-primary-700 disabled:bg-primary-400 text-white rounded-lg transition-colors flex items-center justify-center gap-2"
          >
            {isSendingOtp ? (
              <>
                <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                </svg>
                Sending...
              </>
            ) : (
              <>
                <Mail className="h-4 w-4" />
                Send Verification Code
              </>
            )}
          </button>
        )}

        {/* Input field - show for name, password, or after OTP sent */}
        {(confirmLevel === 'name' || confirmLevel === 'password' || (confirmLevel === 'otp' && otpSent)) && (
          <div className="relative">
            {confirmLevel === 'password' && (
              <Lock className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-400" />
            )}
            {confirmLevel === 'otp' && (
              <Mail className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-400" />
            )}
            <input
              type={confirmLevel === 'password' && !showPassword ? 'password' : 'text'}
              value={inputValue}
              onChange={(e) => handleInputChange(e.target.value)}
              placeholder={getPlaceholder()}
              className={cn(
                "w-full px-4 py-2 border border-gray-300 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:ring-2 focus:ring-primary-500 focus:border-transparent",
                (confirmLevel === 'password' || confirmLevel === 'otp') && "pl-10",
                confirmLevel === 'password' && "pr-10"
              )}
              autoComplete={confirmLevel === 'password' ? 'current-password' : 'off'}
            />
            {confirmLevel === 'password' && (
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
              >
                {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
              </button>
            )}
          </div>
        )}

        {/* Resend OTP link */}
        {confirmLevel === 'otp' && otpSent && (
          <button
            type="button"
            onClick={handleSendOtp}
            disabled={isSendingOtp}
            className="mt-2 text-sm text-primary-600 dark:text-primary-400 hover:underline disabled:opacity-50"
          >
            {isSendingOtp ? 'Sending...' : 'Resend code'}
          </button>
        )}
      </div>
    );
  };

  return (
    <Transition appear show={isOpen} as={Fragment}>
      <Dialog as="div" className="relative z-50" onClose={onClose}>
        <Transition.Child
          as={Fragment}
          enter="ease-out duration-300"
          enterFrom="opacity-0"
          enterTo="opacity-100"
          leave="ease-in duration-200"
          leaveFrom="opacity-100"
          leaveTo="opacity-0"
        >
          <div className="fixed inset-0 bg-black/50 dark:bg-black/70" />
        </Transition.Child>

        <div className="fixed inset-0 overflow-y-auto">
          <div className="flex min-h-full items-center justify-center p-4 text-center">
            <Transition.Child
              as={Fragment}
              enter="ease-out duration-300"
              enterFrom="opacity-0 scale-95"
              enterTo="opacity-100 scale-100"
              leave="ease-in duration-200"
              leaveFrom="opacity-100 scale-100"
              leaveTo="opacity-0 scale-95"
            >
              <Dialog.Panel className="w-full max-w-md transform overflow-hidden rounded-2xl bg-white dark:bg-gray-900 p-6 text-left align-middle shadow-xl transition-all border border-gray-200 dark:border-gray-700">
                <div className="flex items-start gap-4">
                  {IconComponent && (
                    <div className={cn('flex-shrink-0 p-2 rounded-full', styles.iconBg)}>
                      <IconComponent className={cn('h-6 w-6', styles.iconColor)} />
                    </div>
                  )}
                  <div className="flex-1">
                    <Dialog.Title
                      as="h3"
                      className="text-lg font-semibold leading-6 text-gray-900 dark:text-white"
                    >
                      {title}
                    </Dialog.Title>
                    <div className="mt-2">
                      <p className="text-sm text-gray-500 dark:text-gray-400 whitespace-pre-line">
                        {message}
                      </p>
                    </div>
                  </div>
                  <button
                    type="button"
                    className="flex-shrink-0 p-1 text-gray-400 hover:text-gray-500 dark:hover:text-gray-300 rounded-lg"
                    onClick={onClose}
                  >
                    <X className="h-5 w-5" />
                  </button>
                </div>

                {/* Confirmation input based on level */}
                {renderConfirmationInput()}

                {/* Additional content (e.g., checkboxes) */}
                {children && <div className="mt-4">{children}</div>}

                {/* Error message */}
                {error && (
                  <div className="mt-4 p-3 bg-red-50 dark:bg-red-900/30 border border-red-200 dark:border-red-800 rounded-lg">
                    <p className="text-sm text-red-600 dark:text-red-400">{error}</p>
                  </div>
                )}

                <div className="mt-6 flex justify-end gap-3">
                  <button
                    type="button"
                    className="inline-flex justify-center rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700 focus:outline-none focus-visible:ring-2 focus-visible:ring-primary-500 focus-visible:ring-offset-2 transition-colors"
                    onClick={onClose}
                    disabled={isLoading || isValidating}
                  >
                    {cancelText}
                  </button>
                  <button
                    type="button"
                    className={cn(
                      'inline-flex justify-center rounded-lg px-4 py-2 text-sm font-medium focus:outline-none focus-visible:ring-2 focus-visible:ring-offset-2 transition-colors disabled:opacity-50 disabled:cursor-not-allowed',
                      styles.buttonBg,
                      styles.buttonText
                    )}
                    onClick={handleConfirm}
                    disabled={getConfirmDisabled()}
                  >
                    {(isLoading || isValidating) ? (
                      <span className="flex items-center gap-2">
                        <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24">
                          <circle
                            className="opacity-25"
                            cx="12"
                            cy="12"
                            r="10"
                            stroke="currentColor"
                            strokeWidth="4"
                            fill="none"
                          />
                          <path
                            className="opacity-75"
                            fill="currentColor"
                            d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
                          />
                        </svg>
                        {isValidating ? 'Verifying...' : 'Processing...'}
                      </span>
                    ) : (
                      confirmText
                    )}
                  </button>
                </div>
              </Dialog.Panel>
            </Transition.Child>
          </div>
        </div>
      </Dialog>
    </Transition>
  );
}

// Hook for easier usage with state management
export interface UseConfirmDialogOptions {
  onConfirm: () => void | Promise<void>;
  title: string;
  message: string;
  confirmText?: string;
  cancelText?: string;
  variant?: 'danger' | 'warning' | 'default';
  icon?: 'delete' | 'redeploy' | 'warning' | 'stop' | 'none';
  confirmLevel?: ConfirmLevel;
  confirmValue?: string;
  confirmInputPlaceholder?: string;
  confirmInputLabel?: string;
  children?: React.ReactNode;
  onValidate?: (value: string) => Promise<{ valid: boolean; error?: string }>;
  onSendOtp?: () => Promise<{ success: boolean; error?: string }>;
}

export function useConfirmDialog() {
  const [isOpen, setIsOpen] = React.useState(false);
  const [isLoading, setIsLoading] = React.useState(false);
  const [options, setOptions] = React.useState<UseConfirmDialogOptions | null>(null);

  const confirm = React.useCallback((opts: UseConfirmDialogOptions) => {
    setOptions(opts);
    setIsOpen(true);
  }, []);

  const handleConfirm = React.useCallback(async () => {
    if (!options) return;

    setIsLoading(true);
    try {
      await options.onConfirm();
    } finally {
      setIsLoading(false);
      setIsOpen(false);
    }
  }, [options]);

  const handleClose = React.useCallback(() => {
    if (!isLoading) {
      setIsOpen(false);
    }
  }, [isLoading]);

  const dialogProps = {
    isOpen,
    onClose: handleClose,
    onConfirm: handleConfirm,
    title: options?.title ?? '',
    message: options?.message ?? '',
    confirmText: options?.confirmText,
    cancelText: options?.cancelText,
    variant: options?.variant,
    icon: options?.icon,
    isLoading,
    confirmLevel: options?.confirmLevel,
    confirmValue: options?.confirmValue,
    confirmInputPlaceholder: options?.confirmInputPlaceholder,
    confirmInputLabel: options?.confirmInputLabel,
    children: options?.children,
    onValidate: options?.onValidate,
    onSendOtp: options?.onSendOtp,
  };

  return { confirm, dialogProps, ConfirmDialog };
}
