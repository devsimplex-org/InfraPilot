"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";

export default function RegistriesRedirect() {
  const router = useRouter();

  useEffect(() => {
    router.replace("/docker#registries");
  }, [router]);

  return (
    <div className="flex items-center justify-center h-64">
      <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-600" />
    </div>
  );
}
