"use client";
import { redirect } from "next/navigation";
export default function SystemHealthRedirect() {
  redirect("/settings/health");
}
