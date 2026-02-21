import MetricsPage from "../../platform/metrics/page";
import { FeatureGate } from "@/components/ui/FeatureGate";

export default function MonitorMetricsPage() {
  return (
    <FeatureGate feature="advanced_alerts" tier="professional" featureLabel="Metrics & Reports">
      <MetricsPage />
    </FeatureGate>
  );
}
