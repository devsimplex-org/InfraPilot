package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

const (
	ghcrAPIBase = "https://api.github.com"
)

// GHCRClient implements the Client interface for GitHub Container Registry
type GHCRClient struct {
	token     string
	namespace string // User or organization name
	client    *http.Client
}

// NewGHCRClient creates a new GHCR client
func NewGHCRClient(token, namespace string) *GHCRClient {
	return &GHCRClient{
		token:     token,
		namespace: namespace,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Provider returns the provider type
func (c *GHCRClient) Provider() Provider {
	return ProviderGHCR
}

// TestConnection tests the connection to GHCR
func (c *GHCRClient) TestConnection(ctx context.Context) error {
	// Try to get the authenticated user to verify token
	req, err := http.NewRequestWithContext(ctx, "GET", ghcrAPIBase+"/user", nil)
	if err != nil {
		return err
	}

	c.setHeaders(req)

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("authentication failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// ListRepositories lists container packages for the namespace
func (c *GHCRClient) ListRepositories(ctx context.Context, page, pageSize int) (*ListRepositoriesResponse, error) {
	var apiURL string

	// GitHub API uses different endpoints for user vs org packages
	// First, try to determine if namespace is a user or org
	if c.namespace != "" {
		// Try org first, then user
		apiURL = fmt.Sprintf("%s/orgs/%s/packages?package_type=container&per_page=%d&page=%d",
			ghcrAPIBase, url.PathEscape(c.namespace), pageSize, page)
	} else {
		// Use authenticated user's packages
		apiURL = fmt.Sprintf("%s/user/packages?package_type=container&per_page=%d&page=%d",
			ghcrAPIBase, pageSize, page)
	}

	repos, total, err := c.fetchPackages(ctx, apiURL)
	if err != nil {
		// If org endpoint failed, try user endpoint
		if c.namespace != "" {
			apiURL = fmt.Sprintf("%s/users/%s/packages?package_type=container&per_page=%d&page=%d",
				ghcrAPIBase, url.PathEscape(c.namespace), pageSize, page)
			repos, total, err = c.fetchPackages(ctx, apiURL)
			if err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
	}

	return &ListRepositoriesResponse{
		Repositories: repos,
		TotalCount:   total,
		Page:         page,
		PageSize:     pageSize,
	}, nil
}

func (c *GHCRClient) fetchPackages(ctx context.Context, apiURL string) ([]Repository, int, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, 0, err
	}

	c.setHeaders(req)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, 0, fmt.Errorf("failed to list packages: status %d: %s", resp.StatusCode, string(body))
	}

	var packages []ghcrPackage
	if err := json.NewDecoder(resp.Body).Decode(&packages); err != nil {
		return nil, 0, err
	}

	repos := make([]Repository, len(packages))
	for i, p := range packages {
		fullName := p.Name
		if p.Owner != nil {
			fullName = fmt.Sprintf("ghcr.io/%s/%s", p.Owner.Login, p.Name)
		}

		repos[i] = Repository{
			Name:        p.Name,
			FullName:    fullName,
			Description: nilIfEmpty(p.Description),
			IsPrivate:   p.Visibility == "private",
			PullCount:   0, // GitHub API doesn't provide pull count
			UpdatedAt:   nilIfEmpty(p.UpdatedAt),
		}
	}

	// Parse total count from Link header if available
	total := len(packages)
	if linkHeader := resp.Header.Get("Link"); linkHeader != "" {
		// GitHub doesn't provide total count directly, estimate from current page
		total = len(packages)
	}

	return repos, total, nil
}

// ListTags lists tags (versions) for a container package
func (c *GHCRClient) ListTags(ctx context.Context, repository string, page, pageSize int) (*ListTagsResponse, error) {
	var apiURL string

	// GitHub uses "versions" endpoint for package tags
	if c.namespace != "" {
		// Try org first
		apiURL = fmt.Sprintf("%s/orgs/%s/packages/container/%s/versions?per_page=%d&page=%d",
			ghcrAPIBase, url.PathEscape(c.namespace), url.PathEscape(repository), pageSize, page)
	} else {
		apiURL = fmt.Sprintf("%s/user/packages/container/%s/versions?per_page=%d&page=%d",
			ghcrAPIBase, url.PathEscape(repository), pageSize, page)
	}

	tags, total, err := c.fetchVersions(ctx, apiURL)
	if err != nil {
		// If org endpoint failed, try user endpoint
		if c.namespace != "" {
			apiURL = fmt.Sprintf("%s/users/%s/packages/container/%s/versions?per_page=%d&page=%d",
				ghcrAPIBase, url.PathEscape(c.namespace), url.PathEscape(repository), pageSize, page)
			tags, total, err = c.fetchVersions(ctx, apiURL)
			if err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
	}

	return &ListTagsResponse{
		Tags:       tags,
		TotalCount: total,
		Page:       page,
		PageSize:   pageSize,
	}, nil
}

func (c *GHCRClient) fetchVersions(ctx context.Context, apiURL string) ([]Tag, int, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, 0, err
	}

	c.setHeaders(req)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, 0, fmt.Errorf("failed to list versions: status %d: %s", resp.StatusCode, string(body))
	}

	var versions []ghcrVersion
	if err := json.NewDecoder(resp.Body).Decode(&versions); err != nil {
		return nil, 0, err
	}

	// Each version can have multiple tags
	var tags []Tag
	for _, v := range versions {
		// If version has tags (most common case)
		if len(v.Metadata.Container.Tags) > 0 {
			for _, tagName := range v.Metadata.Container.Tags {
				tags = append(tags, Tag{
					Name:      tagName,
					Digest:    nilIfEmpty(v.Name), // Version name is the digest
					SizeBytes: 0,                  // GitHub API doesn't provide size easily
					PushedAt:  nilIfEmpty(v.CreatedAt),
				})
			}
		} else {
			// Untagged version - use digest as name
			tags = append(tags, Tag{
				Name:      v.Name, // Use digest/sha as name
				Digest:    nilIfEmpty(v.Name),
				SizeBytes: 0,
				PushedAt:  nilIfEmpty(v.CreatedAt),
			})
		}
	}

	// Parse total from header if available
	total := len(tags)
	if totalHeader := resp.Header.Get("X-Total-Count"); totalHeader != "" {
		if parsed, err := strconv.Atoi(totalHeader); err == nil {
			total = parsed
		}
	}

	return tags, total, nil
}

func (c *GHCRClient) setHeaders(req *http.Request) {
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
}

// GitHub API response types

type ghcrPackage struct {
	ID          int64       `json:"id"`
	Name        string      `json:"name"`
	PackageType string      `json:"package_type"`
	Visibility  string      `json:"visibility"`
	HTMLURL     string      `json:"html_url"`
	Description string      `json:"description"`
	CreatedAt   string      `json:"created_at"`
	UpdatedAt   string      `json:"updated_at"`
	Owner       *ghcrOwner  `json:"owner"`
}

type ghcrOwner struct {
	Login string `json:"login"`
	Type  string `json:"type"`
}

type ghcrVersion struct {
	ID                  int64        `json:"id"`
	Name                string       `json:"name"` // This is the digest (sha256:...)
	PackageHTMLURL      string       `json:"package_html_url"`
	HTMLURL             string       `json:"html_url"`
	CreatedAt           string       `json:"created_at"`
	UpdatedAt           string       `json:"updated_at"`
	Metadata            ghcrMetadata `json:"metadata"`
}

type ghcrMetadata struct {
	PackageType string             `json:"package_type"`
	Container   ghcrContainerMeta  `json:"container"`
}

type ghcrContainerMeta struct {
	Tags []string `json:"tags"`
}
