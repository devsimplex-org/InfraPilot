"use client";

import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Trophy,
  TrendingUp,
  TrendingDown,
  Shield,
  AlertTriangle,
  CheckCircle,
  Clock,
  Target,
  Users,
  RefreshCw,
} from "lucide-react";
import { api, TeamScore, TeamLeaderboard } from "@/lib/api";
import { cn } from "@/lib/utils";
import { PageHeader } from "@/components/ui/PageHeader";
import { Breadcrumb } from "@/components/ui/Breadcrumb";
import { StatCard, MetricsGrid } from "@/components/ui/StatCard";
import { Table } from "@/components/ui/Table";
import { Card } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { EmptyState } from "@/components/ui/EmptyState";

export default function SecurityMaturityPage() {
  const queryClient = useQueryClient();

  // Fetch team leaderboard
  const { data: leaderboardData, isLoading: loadingLeaderboard } = useQuery({
    queryKey: ["teamLeaderboard"],
    queryFn: () => api.getTeamLeaderboard(),
    refetchInterval: 60000,
  });

  // Calculate all team scores mutation
  const calculateAllScoresMutation = useMutation({
    mutationFn: () => api.calculateAllTeamScores(),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["teamLeaderboard"] });
      queryClient.invalidateQueries({ queryKey: ["latestTeamScores"] });
    },
  });

  const leaderboard = leaderboardData?.leaderboard || [];

  const getScoreColor = (score: number) => {
    if (score >= 80) return "text-green-600 dark:text-green-400";
    if (score >= 60) return "text-yellow-600 dark:text-yellow-400";
    if (score >= 40) return "text-orange-600 dark:text-orange-400";
    return "text-red-600 dark:text-red-400";
  };

  const getScoreBadgeClass = (score: number) => {
    if (score >= 80) return "bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400";
    if (score >= 60) return "bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400";
    if (score >= 40) return "bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400";
    return "bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400";
  };

  const getMaturityLevel = (score: number): "healthy" | "warning" | "degraded" | "critical" => {
    if (score >= 80) return "healthy";
    if (score >= 60) return "warning";
    if (score >= 40) return "degraded";
    return "critical";
  };

  const getRankMedal = (rank: number) => {
    if (rank === 1) return "🥇";
    if (rank === 2) return "🥈";
    if (rank === 3) return "🥉";
    return null;
  };

  const avgScore = leaderboard.length > 0
    ? Math.round(
        leaderboard.reduce((sum, t) => sum + t.overall_score, 0) / leaderboard.length
      )
    : 0;

  const highPerformers = leaderboard.filter((t) => t.overall_score >= 80).length;
  const topScore = leaderboard[0]?.overall_score || 0;

  // Table columns
  const columns = [
    {
      key: "rank",
      header: "Rank",
      width: "100px",
      render: (value: number) => (
        <div className="flex items-center gap-2">
          <span className="text-2xl">{getRankMedal(value)}</span>
          <span className="text-sm font-medium">#{value}</span>
        </div>
      ),
    },
    {
      key: "team_name",
      header: "Team",
      render: (value: string) => (
        <div className="flex items-center gap-2">
          <Users className="h-4 w-4 text-gray-400" />
          <span className="font-medium">{value}</span>
        </div>
      ),
    },
    {
      key: "overall_score",
      header: "Overall",
      align: "center" as const,
      render: (value: number) => (
        <Badge
          variant="status"
          status={getMaturityLevel(value)}
          size="sm"
        >
          {value}
        </Badge>
      ),
    },
    {
      key: "vulnerability_score",
      header: "Vulnerabilities",
      align: "center" as const,
      render: (value: number) => (
        <span className={cn("text-sm font-medium", getScoreColor(value || 0))}>
          {value || "-"}
        </span>
      ),
    },
    {
      key: "policy_score",
      header: "Policy",
      align: "center" as const,
      render: (value: number) => (
        <span className={cn("text-sm font-medium", getScoreColor(value || 0))}>
          {value || "-"}
        </span>
      ),
    },
    {
      key: "response_score",
      header: "Response",
      align: "center" as const,
      render: (value: number) => (
        <span className={cn("text-sm font-medium", getScoreColor(value || 0))}>
          {value || "-"}
        </span>
      ),
    },
    {
      key: "calculated_at",
      header: "Last Updated",
      align: "right" as const,
      render: (value: string) => (
        <span className="text-sm text-gray-500 dark:text-gray-400">
          {new Date(value).toLocaleDateString()}
        </span>
      ),
    },
  ];

  // Recommendation data (mock for now)
  const recommendations = [
    {
      id: 1,
      category: "Vulnerability Management",
      priority: "high",
      description: "Address 12 critical vulnerabilities in production deployments",
      impact: "High",
    },
    {
      id: 2,
      category: "Policy Compliance",
      priority: "medium",
      description: "Update 5 teams to meet latest security policy requirements",
      impact: "Medium",
    },
    {
      id: 3,
      category: "Response Time",
      priority: "high",
      description: "Reduce mean time to fix from 48h to 24h for critical issues",
      impact: "High",
    },
  ];

  const recommendationColumns = [
    {
      key: "category",
      header: "Category",
      render: (value: string) => (
        <div className="font-medium text-gray-900 dark:text-white">{value}</div>
      ),
    },
    {
      key: "description",
      header: "Recommendation",
      render: (value: string) => (
        <div className="text-sm text-gray-600 dark:text-gray-400">{value}</div>
      ),
    },
    {
      key: "priority",
      header: "Priority",
      render: (value: string) => (
        <Badge
          variant="status"
          status={value === "high" ? "critical" : value === "medium" ? "warning" : "healthy"}
          size="sm"
        >
          {value}
        </Badge>
      ),
    },
    {
      key: "impact",
      header: "Impact",
      align: "right" as const,
      render: (value: string) => (
        <span className="text-sm font-medium text-gray-900 dark:text-white">{value}</span>
      ),
    },
  ];

  return (
    <div className="space-y-6">
      <PageHeader
        title="Security Maturity"
        description="Team security scores and performance benchmarks"
        breadcrumbs={
          <Breadcrumb
            items={[
              { label: "Govern", href: "/" },
              { label: "Security Maturity", current: true },
            ]}
          />
        }
        action={
          <button
            onClick={() => calculateAllScoresMutation.mutate()}
            disabled={calculateAllScoresMutation.isPending}
            className="px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 disabled:bg-primary-400 transition-colors flex items-center gap-2"
          >
            <RefreshCw
              className={cn(
                "h-4 w-4",
                calculateAllScoresMutation.isPending && "animate-spin"
              )}
            />
            {calculateAllScoresMutation.isPending ? "Calculating..." : "Recalculate Scores"}
          </button>
        }
      />

      {/* Stats Overview */}
      <MetricsGrid columns={4} className="mb-6">
        <StatCard
          label="Maturity Score"
          value={avgScore}
          icon={Trophy}
          iconColor="text-yellow-600 dark:text-yellow-400"
          description="Average across all teams"
        />
        <StatCard
          label="Improvements Needed"
          value={recommendations.length}
          icon={TrendingUp}
          iconColor="text-blue-600 dark:text-blue-400"
          description="High priority items"
        />
        <StatCard
          label="Areas Covered"
          value={5}
          icon={Shield}
          iconColor="text-green-600 dark:text-green-400"
          description="Security categories"
        />
        <StatCard
          label="High Performers"
          value={highPerformers}
          icon={Target}
          iconColor="text-purple-600 dark:text-purple-400"
          description="Teams with score ≥ 80"
        />
      </MetricsGrid>

      {/* Maturity Breakdown by Category */}
      <div className="mb-6">
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
          Maturity Breakdown by Category
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          <Card>
            <Card.Body>
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-2">
                  <Shield className="h-5 w-5 text-blue-600 dark:text-blue-400" />
                  <h4 className="font-medium text-gray-900 dark:text-white">
                    Vulnerability Management
                  </h4>
                </div>
                <Badge variant="status" status="healthy" size="sm">
                  85
                </Badge>
              </div>
              <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                <div
                  className="bg-green-600 h-2 rounded-full"
                  style={{ width: "85%" }}
                />
              </div>
            </Card.Body>
          </Card>

          <Card>
            <Card.Body>
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-2">
                  <CheckCircle className="h-5 w-5 text-green-600 dark:text-green-400" />
                  <h4 className="font-medium text-gray-900 dark:text-white">
                    Policy Compliance
                  </h4>
                </div>
                <Badge variant="status" status="warning" size="sm">
                  72
                </Badge>
              </div>
              <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                <div
                  className="bg-yellow-600 h-2 rounded-full"
                  style={{ width: "72%" }}
                />
              </div>
            </Card.Body>
          </Card>

          <Card>
            <Card.Body>
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-2">
                  <Clock className="h-5 w-5 text-orange-600 dark:text-orange-400" />
                  <h4 className="font-medium text-gray-900 dark:text-white">
                    Response Time
                  </h4>
                </div>
                <Badge variant="status" status="degraded" size="sm">
                  68
                </Badge>
              </div>
              <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                <div
                  className="bg-orange-600 h-2 rounded-full"
                  style={{ width: "68%" }}
                />
              </div>
            </Card.Body>
          </Card>

          <Card>
            <Card.Body>
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-2">
                  <Target className="h-5 w-5 text-purple-600 dark:text-purple-400" />
                  <h4 className="font-medium text-gray-900 dark:text-white">
                    Deployment Security
                  </h4>
                </div>
                <Badge variant="status" status="healthy" size="sm">
                  78
                </Badge>
              </div>
              <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                <div
                  className="bg-yellow-600 h-2 rounded-full"
                  style={{ width: "78%" }}
                />
              </div>
            </Card.Body>
          </Card>

          <Card>
            <Card.Body>
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-2">
                  <AlertTriangle className="h-5 w-5 text-red-600 dark:text-red-400" />
                  <h4 className="font-medium text-gray-900 dark:text-white">
                    Exception Management
                  </h4>
                </div>
                <Badge variant="status" status="warning" size="sm">
                  65
                </Badge>
              </div>
              <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                <div
                  className="bg-yellow-600 h-2 rounded-full"
                  style={{ width: "65%" }}
                />
              </div>
            </Card.Body>
          </Card>
        </div>
      </div>

      {/* Improvement Recommendations */}
      <div className="mb-6">
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
          Improvement Recommendations
        </h3>
        <Table
          columns={recommendationColumns}
          data={recommendations}
          keyExtractor={(row) => row.id.toString()}
          hoverable={false}
        />
      </div>

      {/* Team Leaderboard */}
      <div>
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
          Team Rankings
        </h3>
        {loadingLeaderboard ? (
          <div className="flex items-center justify-center h-32">
            <RefreshCw className="h-8 w-8 animate-spin text-gray-400" />
          </div>
        ) : leaderboard.length === 0 ? (
          <Card>
            <Card.Body>
              <EmptyState
                icon={Trophy}
                title="No scores yet"
                description="Calculate scores to see team rankings"
              />
            </Card.Body>
          </Card>
        ) : (
          <Table
            columns={columns}
            data={leaderboard}
            keyExtractor={(row) => row.team_name}
            hoverable
          />
        )}
      </div>
    </div>
  );
}
