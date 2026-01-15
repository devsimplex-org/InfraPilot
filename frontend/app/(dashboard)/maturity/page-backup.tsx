"use client";

import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Trophy,
  TrendingUp,
  TrendingDown,
  Minus,
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
import {
  PageLayout,
  ListCard,
  EmptyState,
  Button,
  Tabs,
} from "@/components/ui/page-layout";
import {
  DetailPanel,
  DetailSection,
  DetailRow,
} from "@/components/ui/detail-panel";

type PageTab = "leaderboard" | "teams";

export default function SecurityMaturityPage() {
  const queryClient = useQueryClient();
  const [pageTab, setPageTab] = useState<PageTab>("leaderboard");
  const [selectedTeam, setSelectedTeam] = useState<TeamScore | null>(null);

  // Fetch team leaderboard
  const { data: leaderboardData, isLoading: loadingLeaderboard } = useQuery({
    queryKey: ["teamLeaderboard"],
    queryFn: () => api.getTeamLeaderboard(),
    enabled: pageTab === "leaderboard",
    refetchInterval: 60000, // Refresh every minute
  });

  // Fetch latest team scores
  const { data: teamScoresData, isLoading: loadingTeamScores } = useQuery({
    queryKey: ["latestTeamScores"],
    queryFn: () => api.getLatestTeamScores(),
    enabled: pageTab === "teams",
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
  const teamScores = teamScoresData?.team_scores || [];

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

  const getRankMedal = (rank: number) => {
    if (rank === 1) return "🥇";
    if (rank === 2) return "🥈";
    if (rank === 3) return "🥉";
    return null;
  };

  const formatMTTF = (hours?: number) => {
    if (!hours) return "N/A";
    if (hours < 24) return `${hours.toFixed(1)}h`;
    const days = (hours / 24).toFixed(1);
    return `${days}d`;
  };

  const getVulnerabilityRate = (team: TeamScore) => {
    if (team.total_deployments === 0) return 0;
    return ((team.vulnerable_deployments / team.total_deployments) * 100).toFixed(1);
  };

  return (
    <PageLayout
      title="Security Maturity"
      subtitle="Team security scores and performance benchmarks"
      icon={<Trophy className="h-8 w-8" />}
      action={
        <Button
          onClick={() => calculateAllScoresMutation.mutate()}
          disabled={calculateAllScoresMutation.isPending}
        >
          <RefreshCw
            className={cn(
              "h-4 w-4 mr-2",
              calculateAllScoresMutation.isPending && "animate-spin"
            )}
          />
          {calculateAllScoresMutation.isPending ? "Calculating..." : "Recalculate Scores"}
        </Button>
      }
    >
      <Tabs
        tabs={[
          { id: "leaderboard", label: "Leaderboard", icon: Trophy },
          { id: "teams", label: "Team Scores", icon: Users },
        ]}
        activeTab={pageTab}
        onChange={(tab) => setPageTab(tab as PageTab)}
      />

      {pageTab === "leaderboard" && (
        <div className="space-y-6">
          {/* Stats Overview */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-blue-100 dark:bg-blue-900/30 rounded-lg">
                  <Users className="h-5 w-5 text-blue-600 dark:text-blue-400" />
                </div>
                <div>
                  <p className="text-xs text-gray-600 dark:text-gray-400">Total Teams</p>
                  <p className="text-2xl font-bold">{leaderboard.length}</p>
                </div>
              </div>
            </div>

            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-green-100 dark:bg-green-900/30 rounded-lg">
                  <Trophy className="h-5 w-5 text-green-600 dark:text-green-400" />
                </div>
                <div>
                  <p className="text-xs text-gray-600 dark:text-gray-400">Top Score</p>
                  <p className="text-2xl font-bold">
                    {leaderboard[0]?.overall_score || 0}
                  </p>
                </div>
              </div>
            </div>

            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-yellow-100 dark:bg-yellow-900/30 rounded-lg">
                  <Target className="h-5 w-5 text-yellow-600 dark:text-yellow-400" />
                </div>
                <div>
                  <p className="text-xs text-gray-600 dark:text-gray-400">Average Score</p>
                  <p className="text-2xl font-bold">
                    {leaderboard.length > 0
                      ? Math.round(
                          leaderboard.reduce((sum, t) => sum + t.overall_score, 0) /
                            leaderboard.length
                        )
                      : 0}
                  </p>
                </div>
              </div>
            </div>

            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-purple-100 dark:bg-purple-900/30 rounded-lg">
                  <Shield className="h-5 w-5 text-purple-600 dark:text-purple-400" />
                </div>
                <div>
                  <p className="text-xs text-gray-600 dark:text-gray-400">High Performers</p>
                  <p className="text-2xl font-bold">
                    {leaderboard.filter((t) => t.overall_score >= 80).length}
                  </p>
                </div>
              </div>
            </div>
          </div>

          {/* Leaderboard Table */}
          <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
            <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
              <h3 className="text-lg font-semibold">Team Rankings</h3>
              <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">
                Based on last 30 days performance
              </p>
            </div>

            {loadingLeaderboard ? (
              <div className="flex items-center justify-center h-64">
                <RefreshCw className="h-8 w-8 animate-spin text-gray-400" />
              </div>
            ) : leaderboard.length === 0 ? (
              <div className="p-12">
                <EmptyState
                  icon={Trophy}
                  title="No scores yet"
                  description="Calculate scores to see team rankings"
                />
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead className="bg-gray-50 dark:bg-gray-900">
                    <tr>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                        Rank
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                        Team
                      </th>
                      <th className="px-6 py-3 text-center text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                        Overall
                      </th>
                      <th className="px-6 py-3 text-center text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                        Vulnerabilities
                      </th>
                      <th className="px-6 py-3 text-center text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                        Policy
                      </th>
                      <th className="px-6 py-3 text-center text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                        Response
                      </th>
                      <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                        Last Updated
                      </th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
                    {leaderboard.map((team) => (
                      <tr
                        key={team.team_name}
                        className="hover:bg-gray-50 dark:hover:bg-gray-900/50 transition-colors"
                      >
                        <td className="px-6 py-4 whitespace-nowrap">
                          <div className="flex items-center gap-2">
                            <span className="text-2xl">{getRankMedal(team.rank)}</span>
                            <span className="text-sm font-medium">#{team.rank}</span>
                          </div>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <div className="flex items-center gap-2">
                            <Users className="h-4 w-4 text-gray-400" />
                            <span className="font-medium">{team.team_name}</span>
                          </div>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-center">
                          <span
                            className={cn(
                              "inline-flex items-center px-3 py-1 rounded-full text-sm font-semibold",
                              getScoreBadgeClass(team.overall_score)
                            )}
                          >
                            {team.overall_score}
                          </span>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-center">
                          <span className={cn("text-sm", getScoreColor(team.vulnerability_score || 0))}>
                            {team.vulnerability_score || "-"}
                          </span>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-center">
                          <span className={cn("text-sm", getScoreColor(team.policy_score || 0))}>
                            {team.policy_score || "-"}
                          </span>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-center">
                          <span className={cn("text-sm", getScoreColor(team.response_score || 0))}>
                            {team.response_score || "-"}
                          </span>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-right text-sm text-gray-500">
                          {new Date(team.calculated_at).toLocaleDateString()}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}

      {pageTab === "teams" && (
        <div className="flex flex-col lg:flex-row gap-6 h-full">
          {/* Team List */}
          <div className="lg:w-1/2">
            {loadingTeamScores ? (
              <div className="flex items-center justify-center h-64">
                <RefreshCw className="h-8 w-8 animate-spin text-gray-400" />
              </div>
            ) : teamScores.length === 0 ? (
              <EmptyState
                icon={Users}
                title="No team scores"
                description="Calculate team scores to view detailed metrics"
              />
            ) : (
              <div className="space-y-2">
                {teamScores.map((team) => (
                  <ListCard
                    key={team.team_name}
                    selected={selectedTeam?.team_name === team.team_name}
                    onClick={() => setSelectedTeam(team)}
                  >
                    <div className="flex items-start justify-between">
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 mb-2">
                          <Users className="h-4 w-4 text-purple-600" />
                          <span className="font-medium text-sm">{team.team_name}</span>
                        </div>
                        <div className="grid grid-cols-2 gap-2 text-xs">
                          <div>
                            <span className="text-gray-600 dark:text-gray-400">
                              Deployments:
                            </span>{" "}
                            <span className="font-medium">{team.total_deployments}</span>
                          </div>
                          <div>
                            <span className="text-gray-600 dark:text-gray-400">MTTF:</span>{" "}
                            <span className="font-medium">
                              {formatMTTF(team.mean_time_to_fix_hours)}
                            </span>
                          </div>
                        </div>
                      </div>
                      <div className="flex flex-col items-end gap-2 ml-4">
                        <span
                          className={cn(
                            "px-3 py-1 text-sm font-bold rounded-full",
                            getScoreBadgeClass(team.overall_score)
                          )}
                        >
                          {team.overall_score}
                        </span>
                        <span className="text-xs text-gray-500">
                          {new Date(team.calculated_at).toLocaleDateString()}
                        </span>
                      </div>
                    </div>
                  </ListCard>
                ))}
              </div>
            )}
          </div>

          {/* Team Detail */}
          <div className="lg:w-1/2">
            {selectedTeam ? (
              <DetailPanel
                title={selectedTeam.team_name}
                onClose={() => setSelectedTeam(null)}
              >
                <DetailSection title="Overall Score">
                  <div className="flex items-center justify-between mb-4">
                    <div className="text-4xl font-bold">
                      <span className={getScoreColor(selectedTeam.overall_score)}>
                        {selectedTeam.overall_score}
                      </span>
                      <span className="text-gray-400 text-2xl">/100</span>
                    </div>
                    <div className="text-sm text-gray-600 dark:text-gray-400">
                      Last calculated:{" "}
                      {new Date(selectedTeam.calculated_at).toLocaleString()}
                    </div>
                  </div>

                  {/* Score breakdown */}
                  <div className="space-y-3">
                    {selectedTeam.vulnerability_score !== undefined && (
                      <div>
                        <div className="flex items-center justify-between mb-1">
                          <div className="flex items-center gap-2">
                            <Shield className="h-4 w-4 text-gray-600" />
                            <span className="text-sm font-medium">
                              Vulnerability Management
                            </span>
                          </div>
                          <span
                            className={cn(
                              "text-sm font-semibold",
                              getScoreColor(selectedTeam.vulnerability_score)
                            )}
                          >
                            {selectedTeam.vulnerability_score}
                          </span>
                        </div>
                        <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                          <div
                            className={cn(
                              "h-2 rounded-full transition-all",
                              selectedTeam.vulnerability_score >= 80
                                ? "bg-green-600"
                                : selectedTeam.vulnerability_score >= 60
                                ? "bg-yellow-600"
                                : "bg-red-600"
                            )}
                            style={{ width: `${selectedTeam.vulnerability_score}%` }}
                          />
                        </div>
                      </div>
                    )}

                    {selectedTeam.policy_score !== undefined && (
                      <div>
                        <div className="flex items-center justify-between mb-1">
                          <div className="flex items-center gap-2">
                            <CheckCircle className="h-4 w-4 text-gray-600" />
                            <span className="text-sm font-medium">Policy Compliance</span>
                          </div>
                          <span
                            className={cn(
                              "text-sm font-semibold",
                              getScoreColor(selectedTeam.policy_score)
                            )}
                          >
                            {selectedTeam.policy_score}
                          </span>
                        </div>
                        <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                          <div
                            className={cn(
                              "h-2 rounded-full transition-all",
                              selectedTeam.policy_score >= 80
                                ? "bg-green-600"
                                : selectedTeam.policy_score >= 60
                                ? "bg-yellow-600"
                                : "bg-red-600"
                            )}
                            style={{ width: `${selectedTeam.policy_score}%` }}
                          />
                        </div>
                      </div>
                    )}

                    {selectedTeam.deployment_score !== undefined && (
                      <div>
                        <div className="flex items-center justify-between mb-1">
                          <div className="flex items-center gap-2">
                            <Target className="h-4 w-4 text-gray-600" />
                            <span className="text-sm font-medium">Deployment Security</span>
                          </div>
                          <span
                            className={cn(
                              "text-sm font-semibold",
                              getScoreColor(selectedTeam.deployment_score)
                            )}
                          >
                            {selectedTeam.deployment_score}
                          </span>
                        </div>
                        <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                          <div
                            className={cn(
                              "h-2 rounded-full transition-all",
                              selectedTeam.deployment_score >= 80
                                ? "bg-green-600"
                                : selectedTeam.deployment_score >= 60
                                ? "bg-yellow-600"
                                : "bg-red-600"
                            )}
                            style={{ width: `${selectedTeam.deployment_score}%` }}
                          />
                        </div>
                      </div>
                    )}

                    {selectedTeam.exception_score !== undefined && (
                      <div>
                        <div className="flex items-center justify-between mb-1">
                          <div className="flex items-center gap-2">
                            <AlertTriangle className="h-4 w-4 text-gray-600" />
                            <span className="text-sm font-medium">Exception Management</span>
                          </div>
                          <span
                            className={cn(
                              "text-sm font-semibold",
                              getScoreColor(selectedTeam.exception_score)
                            )}
                          >
                            {selectedTeam.exception_score}
                          </span>
                        </div>
                        <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                          <div
                            className={cn(
                              "h-2 rounded-full transition-all",
                              selectedTeam.exception_score >= 80
                                ? "bg-green-600"
                                : selectedTeam.exception_score >= 60
                                ? "bg-yellow-600"
                                : "bg-red-600"
                            )}
                            style={{ width: `${selectedTeam.exception_score}%` }}
                          />
                        </div>
                      </div>
                    )}

                    {selectedTeam.response_score !== undefined && (
                      <div>
                        <div className="flex items-center justify-between mb-1">
                          <div className="flex items-center gap-2">
                            <Clock className="h-4 w-4 text-gray-600" />
                            <span className="text-sm font-medium">Response Time</span>
                          </div>
                          <span
                            className={cn(
                              "text-sm font-semibold",
                              getScoreColor(selectedTeam.response_score)
                            )}
                          >
                            {selectedTeam.response_score}
                          </span>
                        </div>
                        <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                          <div
                            className={cn(
                              "h-2 rounded-full transition-all",
                              selectedTeam.response_score >= 80
                                ? "bg-green-600"
                                : selectedTeam.response_score >= 60
                                ? "bg-yellow-600"
                                : "bg-red-600"
                            )}
                            style={{ width: `${selectedTeam.response_score}%` }}
                          />
                        </div>
                      </div>
                    )}
                  </div>
                </DetailSection>

                <DetailSection title="Metrics">
                  <DetailRow label="Total Deployments">
                    <span className="font-semibold">{selectedTeam.total_deployments}</span>
                  </DetailRow>
                  <DetailRow label="Vulnerable Deployments">
                    <div className="flex items-center gap-2">
                      <span className="font-semibold">
                        {selectedTeam.vulnerable_deployments}
                      </span>
                      <span className="text-xs text-gray-500">
                        ({getVulnerabilityRate(selectedTeam)}%)
                      </span>
                    </div>
                  </DetailRow>
                  <DetailRow label="Critical Vulnerabilities">
                    <span
                      className={cn(
                        "font-semibold",
                        selectedTeam.critical_vulnerabilities > 0
                          ? "text-red-600"
                          : "text-green-600"
                      )}
                    >
                      {selectedTeam.critical_vulnerabilities}
                    </span>
                  </DetailRow>
                  <DetailRow label="High Vulnerabilities">
                    <span
                      className={cn(
                        "font-semibold",
                        selectedTeam.high_vulnerabilities > 0
                          ? "text-orange-600"
                          : "text-green-600"
                      )}
                    >
                      {selectedTeam.high_vulnerabilities}
                    </span>
                  </DetailRow>
                  <DetailRow label="Mean Time To Fix">
                    <div className="flex items-center gap-2">
                      <Clock className="h-4 w-4 text-gray-400" />
                      <span className="font-semibold">
                        {formatMTTF(selectedTeam.mean_time_to_fix_hours)}
                      </span>
                    </div>
                  </DetailRow>
                </DetailSection>
              </DetailPanel>
            ) : (
              <EmptyState
                icon={Users}
                title="Select a team"
                description="Click on a team to view detailed security metrics"
              />
            )}
          </div>
        </div>
      )}
    </PageLayout>
  );
}
