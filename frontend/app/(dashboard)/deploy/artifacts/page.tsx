"use client";

import { useQuery } from "@tanstack/react-query";
import { Box, Shield, Package } from "lucide-react";
import { Image } from "lucide-react";
import { api } from "@/lib/api";
import { StatCard, MetricsGrid } from "@/components/ui/StatCard";

export default function ArtifactsOverviewPage() {
  const { data: agents } = useQuery({
    queryKey: ["agents"],
    queryFn: () => api.getAgents(),
  });
  const defaultAgentId = agents?.[0]?.id;

  const { data: imagesData } = useQuery({
    queryKey: ["docker-images", defaultAgentId],
    queryFn: () => api.getDockerImages(defaultAgentId!),
    enabled: !!defaultAgentId,
  });

  const { data: scansData } = useQuery({
    queryKey: ["scans"],
    queryFn: () => api.listScans(),
  });

  const { data: sbomsData } = useQuery({
    queryKey: ["sboms"],
    queryFn: () => api.listSBOMs(),
  });

  const { data: registriesData } = useQuery({
    queryKey: ["registries"],
    queryFn: () => api.getRegistries(),
  });

  return (
    <MetricsGrid columns={4}>
      <StatCard
        label="Images"
        value={imagesData?.length || 0}
        icon={Image}
        iconColor="text-blue-600"
      />
      <StatCard
        label="Scans"
        value={scansData?.length || 0}
        icon={Shield}
        iconColor="text-purple-600"
      />
      <StatCard
        label="SBOMs"
        value={sbomsData?.length || 0}
        icon={Package}
        iconColor="text-green-600"
      />
      <StatCard
        label="Registries"
        value={registriesData?.length || 0}
        icon={Box}
        iconColor="text-orange-600"
      />
    </MetricsGrid>
  );
}
