'use client';

import { useQuery } from '@tanstack/react-query';
import { ReactNode } from 'react';
import { api } from '@/lib/api';
import { UpgradePrompt } from './UpgradePrompt';

interface FeatureGateProps {
  /** Feature key to check, e.g. "secrets_management" */
  feature: string;
  /** Tier required — drives the upgrade prompt colour and label */
  tier: 'professional' | 'enterprise';
  /** Human-readable feature name shown in the upgrade prompt */
  featureLabel: string;
  children: ReactNode;
}

/**
 * Wraps page content that requires a specific license feature.
 * Uses the same TanStack Query key as the dashboard layout so the
 * license data is already in cache when the user navigates here.
 */
export function FeatureGate({ feature, tier, featureLabel, children }: FeatureGateProps) {
  const { data } = useQuery({
    queryKey: ['licenseTierInfo'],
    queryFn: () => api.getLicenseTierInfo(),
    staleTime: 5 * 60 * 1000,
  });

  // No data yet (very first render before cache is populated) — render nothing
  // to avoid flashing gated content. In practice this is imperceptible because
  // the dashboard layout already fetched this.
  if (!data) return null;

  if (!data.features.includes(feature)) {
    return <UpgradePrompt feature={featureLabel} tier={tier} />;
  }

  return <>{children}</>;
}
