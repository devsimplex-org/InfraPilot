import JobsPage from "../platform/jobs/page";
import { FeatureGate } from "@/components/ui/FeatureGate";

export default function MonitorPage() {
  return (
    <FeatureGate feature="advanced_alerts" tier="professional" featureLabel="Background Jobs">
      <JobsPage />
    </FeatureGate>
  );
}
