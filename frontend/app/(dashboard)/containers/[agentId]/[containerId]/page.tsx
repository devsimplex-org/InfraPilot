import { redirect } from "next/navigation";

export default function ContainerDetailRedirect({
  params,
}: {
  params: { agentId: string; containerId: string };
}) {
  redirect(`/docker/containers/${params.agentId}/${params.containerId}`);
}
