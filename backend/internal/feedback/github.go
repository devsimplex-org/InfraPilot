package feedback

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/go-github/v57/github"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

// GitHubDeliverer delivers feedback to GitHub via PR/commit comments and status checks
type GitHubDeliverer struct {
	logger *zap.Logger
	token  string
	client *github.Client
}

// NewGitHubDeliverer creates a new GitHub feedback deliverer
func NewGitHubDeliverer(token string, logger *zap.Logger) *GitHubDeliverer {
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: token},
	)
	tc := oauth2.NewClient(context.Background(), ts)
	client := github.NewClient(tc)

	return &GitHubDeliverer{
		logger: logger,
		token:  token,
		client: client,
	}
}

// Provider returns the provider type
func (g *GitHubDeliverer) Provider() Provider {
	return ProviderGitHub
}

// DeliverPRComment posts a comment on a pull request
func (g *GitHubDeliverer) DeliverPRComment(ctx context.Context, target Target, content FeedbackContent) (string, error) {
	if target.PullRequest == nil {
		return "", fmt.Errorf("PR number is required")
	}

	owner, repo, err := parseRepoFullName(target.RepoFullName)
	if err != nil {
		return "", err
	}

	// Format comment body
	body := g.formatComment(content)

	// Post comment
	comment, _, err := g.client.Issues.CreateComment(ctx, owner, repo, *target.PullRequest, &github.IssueComment{
		Body: github.String(body),
	})
	if err != nil {
		return "", fmt.Errorf("failed to create PR comment: %w", err)
	}

	g.logger.Info("posted GitHub PR comment",
		zap.String("repo", target.RepoFullName),
		zap.Int("pr", *target.PullRequest),
		zap.Int64("comment_id", comment.GetID()),
	)

	return fmt.Sprintf("%d", comment.GetID()), nil
}

// DeliverCommitComment posts a comment on a commit
func (g *GitHubDeliverer) DeliverCommitComment(ctx context.Context, target Target, content FeedbackContent) (string, error) {
	if target.CommitSHA == nil {
		return "", fmt.Errorf("commit SHA is required")
	}

	owner, repo, err := parseRepoFullName(target.RepoFullName)
	if err != nil {
		return "", err
	}

	// Format comment body
	body := g.formatComment(content)

	// Post commit comment
	comment, _, err := g.client.Repositories.CreateComment(ctx, owner, repo, *target.CommitSHA, &github.RepositoryComment{
		Body: github.String(body),
	})
	if err != nil {
		return "", fmt.Errorf("failed to create commit comment: %w", err)
	}

	g.logger.Info("posted GitHub commit comment",
		zap.String("repo", target.RepoFullName),
		zap.String("sha", *target.CommitSHA),
		zap.Int64("comment_id", comment.GetID()),
	)

	return fmt.Sprintf("%d", comment.GetID()), nil
}

// UpdatePRStatus updates the status check on a PR
func (g *GitHubDeliverer) UpdatePRStatus(ctx context.Context, target Target, status PRStatus) error {
	if target.CommitSHA == nil {
		return fmt.Errorf("commit SHA is required for status check")
	}

	owner, repo, err := parseRepoFullName(target.RepoFullName)
	if err != nil {
		return err
	}

	// Create status
	repoStatus := &github.RepoStatus{
		State:       github.String(status.State),
		Context:     github.String(status.Context),
		Description: github.String(status.Description),
	}

	if status.TargetURL != nil {
		repoStatus.TargetURL = github.String(*status.TargetURL)
	}

	_, _, err = g.client.Repositories.CreateStatus(ctx, owner, repo, *target.CommitSHA, repoStatus)
	if err != nil {
		return fmt.Errorf("failed to create status: %w", err)
	}

	g.logger.Info("updated GitHub PR status",
		zap.String("repo", target.RepoFullName),
		zap.String("sha", *target.CommitSHA),
		zap.String("state", status.State),
		zap.String("context", status.Context),
	)

	return nil
}

// formatComment formats the feedback content as a GitHub comment
func (g *GitHubDeliverer) formatComment(content FeedbackContent) string {
	var builder strings.Builder

	// Emoji based on severity
	emoji := g.severityEmoji(content.Severity)

	// Title
	builder.WriteString(fmt.Sprintf("## %s %s\n\n", emoji, content.Title))

	// Message
	builder.WriteString(content.Message)
	builder.WriteString("\n\n")

	// Remediation
	if content.Remediation != "" {
		builder.WriteString(content.Remediation)
		builder.WriteString("\n\n")
	}

	// Footer
	builder.WriteString("---\n")
	builder.WriteString("*Automated security feedback from InfraPilot*\n")

	return builder.String()
}

// severityEmoji returns an emoji for the severity level
func (g *GitHubDeliverer) severityEmoji(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "🔴"
	case "high":
		return "🟠"
	case "medium":
		return "🟡"
	case "low":
		return "🔵"
	default:
		return "⚪"
	}
}

// parseRepoFullName parses "owner/repo" into owner and repo
func parseRepoFullName(fullName string) (owner, repo string, err error) {
	parts := strings.Split(fullName, "/")
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid repo format: expected 'owner/repo', got '%s'", fullName)
	}
	return parts[0], parts[1], nil
}
