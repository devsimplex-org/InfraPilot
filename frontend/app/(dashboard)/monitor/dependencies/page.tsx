import DependenciesPage from "../../dependencies/page";
import { FeatureGate } from "@/components/ui/FeatureGate";

export default function MonitorDependenciesPage() {
  return (
    <FeatureGate feature="advanced_alerts" tier="professional" featureLabel="Dependencies">
      <DependenciesPage />
    </FeatureGate>
  );
}
