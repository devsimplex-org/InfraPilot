package webhook

import (
	"encoding/json"
	"fmt"
)

// Parser interface for extracting build metadata from different CI providers
type Parser interface {
	Parse(payload []byte) (*BuildMetadata, error)
	Provider() string
}

// ==================== GitHub Actions Parser ====================

type GitHubActionsParser struct{}

type githubPayload struct {
	Repository struct {
		FullName string `json:"full_name"`
		CloneURL string `json:"clone_url"`
		HTMLURL  string `json:"html_url"`
	} `json:"repository"`
	HeadCommit struct {
		ID      string `json:"id"`
		Message string `json:"message"`
		Author  struct {
			Name  string `json:"name"`
			Email string `json:"email"`
		} `json:"author"`
	} `json:"head_commit"`
	Ref        string `json:"ref"`
	WorkflowRun struct {
		ID         int64  `json:"id"`
		RunNumber  int    `json:"run_number"`
		HTMLURL    string `json:"html_url"`
		HeadBranch string `json:"head_branch"`
		HeadSHA    string `json:"head_sha"`
	} `json:"workflow_run"`
	Deployment struct {
		ImageRepository string  `json:"image_repository"`
		ImageTag        string  `json:"image_tag"`
		ImageDigest     *string `json:"image_digest"`
	} `json:"deployment"`
	ClientPayload struct {
		ImageRepository string  `json:"image_repository"`
		ImageTag        string  `json:"image_tag"`
		ImageDigest     *string `json:"image_digest"`
	} `json:"client_payload"`
}

func (p *GitHubActionsParser) Parse(payload []byte) (*BuildMetadata, error) {
	var gh githubPayload
	if err := json.Unmarshal(payload, &gh); err != nil {
		return nil, fmt.Errorf("failed to parse GitHub payload: %w", err)
	}

	// Extract branch from ref (refs/heads/main -> main)
	branch := gh.Ref
	if gh.WorkflowRun.HeadBranch != "" {
		branch = gh.WorkflowRun.HeadBranch
	} else if len(branch) > 11 && branch[:11] == "refs/heads/" {
		branch = branch[11:]
	}

	// Determine commit SHA
	commit := gh.HeadCommit.ID
	if gh.WorkflowRun.HeadSHA != "" {
		commit = gh.WorkflowRun.HeadSHA
	}

	// Extract image info (priority: deployment > client_payload)
	imageRepo := gh.Deployment.ImageRepository
	imageTag := gh.Deployment.ImageTag
	imageDigest := gh.Deployment.ImageDigest

	if imageRepo == "" {
		imageRepo = gh.ClientPayload.ImageRepository
		imageTag = gh.ClientPayload.ImageTag
		imageDigest = gh.ClientPayload.ImageDigest
	}

	if imageRepo == "" || imageTag == "" {
		return nil, fmt.Errorf("missing required image_repository or image_tag in payload")
	}

	// Build URL
	buildURL := gh.WorkflowRun.HTMLURL
	if buildURL == "" && gh.Repository.HTMLURL != "" {
		buildURL = fmt.Sprintf("%s/commit/%s", gh.Repository.HTMLURL, commit)
	}

	// Pipeline ID
	pipelineID := fmt.Sprintf("%d", gh.WorkflowRun.ID)
	if pipelineID == "0" {
		pipelineID = commit[:8]
	}

	buildNumber := fmt.Sprintf("%d", gh.WorkflowRun.RunNumber)

	metadata := &BuildMetadata{
		GitRepo:      gh.Repository.CloneURL,
		GitBranch:    branch,
		GitCommit:    commit,
		CommitMsg:    &gh.HeadCommit.Message,
		Author:       &gh.HeadCommit.Author.Name,
		CIProvider:   "github",
		CIPipelineID: pipelineID,
		CIBuildURL:   buildURL,
		BuildNumber:  &buildNumber,
		ImageRepo:    imageRepo,
		ImageTag:     imageTag,
		ImageDigest:  imageDigest,
	}

	return metadata, nil
}

func (p *GitHubActionsParser) Provider() string {
	return "github"
}

// ==================== GitLab CI Parser ====================

type GitLabCIParser struct{}

type gitlabPayload struct {
	ObjectKind string `json:"object_kind"`
	Project    struct {
		Name            string `json:"name"`
		GitHTTPURL      string `json:"git_http_url"`
		WebURL          string `json:"web_url"`
		PathWithNamespace string `json:"path_with_namespace"`
	} `json:"project"`
	Commit struct {
		ID      string `json:"id"`
		Message string `json:"message"`
		Author  struct {
			Name  string `json:"name"`
			Email string `json:"email"`
		} `json:"author"`
	} `json:"commit"`
	Ref   string `json:"ref"`
	Build struct {
		ID         int64  `json:"id"`
		Stage      string `json:"stage"`
		Name       string `json:"name"`
		Status     string `json:"status"`
		StartedAt  string `json:"started_at"`
		FinishedAt string `json:"finished_at"`
	} `json:"build"`
	Pipeline struct {
		ID     int64  `json:"id"`
		WebURL string `json:"web_url"`
		Source string `json:"source"`
	} `json:"pipeline"`
	Builds []struct {
		ID   int64  `json:"id"`
		Name string `json:"name"`
	} `json:"builds"`
	Deployment struct {
		ImageRepository string  `json:"image_repository"`
		ImageTag        string  `json:"image_tag"`
		ImageDigest     *string `json:"image_digest"`
	} `json:"deployment"`
}

func (p *GitLabCIParser) Parse(payload []byte) (*BuildMetadata, error) {
	var gl gitlabPayload
	if err := json.Unmarshal(payload, &gl); err != nil {
		return nil, fmt.Errorf("failed to parse GitLab payload: %w", err)
	}

	// Extract branch from ref (refs/heads/main -> main)
	branch := gl.Ref
	if len(branch) > 11 && branch[:11] == "refs/heads/" {
		branch = branch[11:]
	}

	// Image info from deployment object
	imageRepo := gl.Deployment.ImageRepository
	imageTag := gl.Deployment.ImageTag
	imageDigest := gl.Deployment.ImageDigest

	if imageRepo == "" || imageTag == "" {
		return nil, fmt.Errorf("missing required image_repository or image_tag in deployment object")
	}

	// Build URL
	buildURL := gl.Pipeline.WebURL
	if buildURL == "" {
		buildURL = fmt.Sprintf("%s/-/commit/%s", gl.Project.WebURL, gl.Commit.ID)
	}

	pipelineID := fmt.Sprintf("%d", gl.Pipeline.ID)
	buildNumber := pipelineID

	metadata := &BuildMetadata{
		GitRepo:      gl.Project.GitHTTPURL,
		GitBranch:    branch,
		GitCommit:    gl.Commit.ID,
		CommitMsg:    &gl.Commit.Message,
		Author:       &gl.Commit.Author.Name,
		CIProvider:   "gitlab",
		CIPipelineID: pipelineID,
		CIBuildURL:   buildURL,
		BuildNumber:  &buildNumber,
		ImageRepo:    imageRepo,
		ImageTag:     imageTag,
		ImageDigest:  imageDigest,
	}

	return metadata, nil
}

func (p *GitLabCIParser) Provider() string {
	return "gitlab"
}

// ==================== Generic Parser ====================

type GenericParser struct{}

type genericPayload struct {
	GitRepo         string  `json:"git_repo" binding:"required"`
	GitBranch       string  `json:"git_branch" binding:"required"`
	GitCommit       string  `json:"git_commit" binding:"required"`
	CommitMessage   *string `json:"commit_message"`
	Author          *string `json:"author"`
	CIProvider      string  `json:"ci_provider"`
	CIPipelineID    string  `json:"ci_pipeline_id"`
	CIBuildURL      string  `json:"ci_build_url"`
	BuildNumber     *string `json:"build_number"`
	ImageRepository string  `json:"image_repository" binding:"required"`
	ImageTag        string  `json:"image_tag" binding:"required"`
	ImageDigest     *string `json:"image_digest"`
}

func (p *GenericParser) Parse(payload []byte) (*BuildMetadata, error) {
	var gen genericPayload
	if err := json.Unmarshal(payload, &gen); err != nil {
		return nil, fmt.Errorf("failed to parse generic payload: %w", err)
	}

	// Validate required fields
	if gen.GitRepo == "" || gen.GitBranch == "" || gen.GitCommit == "" {
		return nil, fmt.Errorf("missing required git fields")
	}
	if gen.ImageRepository == "" || gen.ImageTag == "" {
		return nil, fmt.Errorf("missing required image fields")
	}

	provider := gen.CIProvider
	if provider == "" {
		provider = "generic"
	}

	metadata := &BuildMetadata{
		GitRepo:      gen.GitRepo,
		GitBranch:    gen.GitBranch,
		GitCommit:    gen.GitCommit,
		CommitMsg:    gen.CommitMessage,
		Author:       gen.Author,
		CIProvider:   provider,
		CIPipelineID: gen.CIPipelineID,
		CIBuildURL:   gen.CIBuildURL,
		BuildNumber:  gen.BuildNumber,
		ImageRepo:    gen.ImageRepository,
		ImageTag:     gen.ImageTag,
		ImageDigest:  gen.ImageDigest,
	}

	return metadata, nil
}

func (p *GenericParser) Provider() string {
	return "generic"
}

// ==================== Parser Factory ====================

func GetParser(provider string) (Parser, error) {
	switch provider {
	case "github":
		return &GitHubActionsParser{}, nil
	case "gitlab":
		return &GitLabCIParser{}, nil
	case "generic", "jenkins":
		return &GenericParser{}, nil
	default:
		return nil, fmt.Errorf("unsupported provider: %s", provider)
	}
}
