package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

const (
	dockerHubAPIBase  = "https://hub.docker.com/v2"
	dockerHubAuthURL  = "https://hub.docker.com/v2/users/login"
	dockerHubTokenURL = "https://auth.docker.io/token"
)

// DockerHubClient implements the Client interface for Docker Hub
type DockerHubClient struct {
	username  string
	password  string
	namespace string
	token     string // JWT token obtained from login
	client    *http.Client
}

// NewDockerHubClient creates a new Docker Hub client
func NewDockerHubClient(username, password, namespace string) *DockerHubClient {
	return &DockerHubClient{
		username:  username,
		password:  password,
		namespace: namespace,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Provider returns the provider type
func (c *DockerHubClient) Provider() Provider {
	return ProviderDockerHub
}

// TestConnection tests the connection to Docker Hub
func (c *DockerHubClient) TestConnection(ctx context.Context) error {
	// Authenticate to get a token
	if err := c.authenticate(ctx); err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}

	// Try to list repositories to verify access
	_, err := c.ListRepositories(ctx, 1, 1)
	if err != nil {
		return fmt.Errorf("failed to list repositories: %w", err)
	}

	return nil
}

// authenticate gets a JWT token from Docker Hub
func (c *DockerHubClient) authenticate(ctx context.Context) error {
	payload := map[string]string{
		"username": c.username,
		"password": c.password,
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", dockerHubAuthURL, nil)
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Body = io.NopCloser(jsonReader(jsonPayload))

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("authentication failed with status %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Token string `json:"token"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}

	c.token = result.Token
	return nil
}

// ListRepositories lists repositories for the namespace
func (c *DockerHubClient) ListRepositories(ctx context.Context, page, pageSize int) (*ListRepositoriesResponse, error) {
	if c.token == "" {
		if err := c.authenticate(ctx); err != nil {
			return nil, err
		}
	}

	namespace := c.namespace
	if namespace == "" {
		namespace = c.username
	}

	// Docker Hub uses page_size and page parameters
	apiURL := fmt.Sprintf("%s/repositories/%s/?page_size=%d&page=%d",
		dockerHubAPIBase, url.PathEscape(namespace), pageSize, page)

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "JWT "+c.token)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		// Token expired, try to re-authenticate
		if err := c.authenticate(ctx); err != nil {
			return nil, err
		}
		return c.ListRepositories(ctx, page, pageSize)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to list repositories: status %d: %s", resp.StatusCode, string(body))
	}

	var result dockerHubReposResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	repos := make([]Repository, len(result.Results))
	for i, r := range result.Results {
		repos[i] = Repository{
			Name:        r.Name,
			FullName:    fmt.Sprintf("%s/%s", namespace, r.Name),
			Description: nilIfEmpty(r.Description),
			IsPrivate:   r.IsPrivate,
			PullCount:   r.PullCount,
			UpdatedAt:   nilIfEmpty(r.LastUpdated),
		}
	}

	return &ListRepositoriesResponse{
		Repositories: repos,
		TotalCount:   result.Count,
		Page:         page,
		PageSize:     pageSize,
	}, nil
}

// ListTags lists tags for a repository
func (c *DockerHubClient) ListTags(ctx context.Context, repository string, page, pageSize int) (*ListTagsResponse, error) {
	if c.token == "" {
		if err := c.authenticate(ctx); err != nil {
			return nil, err
		}
	}

	namespace := c.namespace
	if namespace == "" {
		namespace = c.username
	}

	// Docker Hub tags API
	apiURL := fmt.Sprintf("%s/repositories/%s/%s/tags/?page_size=%d&page=%d",
		dockerHubAPIBase, url.PathEscape(namespace), url.PathEscape(repository), pageSize, page)

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "JWT "+c.token)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		// Token expired, try to re-authenticate
		if err := c.authenticate(ctx); err != nil {
			return nil, err
		}
		return c.ListTags(ctx, repository, page, pageSize)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to list tags: status %d: %s", resp.StatusCode, string(body))
	}

	var result dockerHubTagsResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	tags := make([]Tag, len(result.Results))
	for i, t := range result.Results {
		var sizeBytes int64
		if len(t.Images) > 0 {
			sizeBytes = t.Images[0].Size
		}

		tags[i] = Tag{
			Name:      t.Name,
			Digest:    nilIfEmpty(t.Digest),
			SizeBytes: sizeBytes,
			PushedAt:  nilIfEmpty(t.LastUpdated),
		}
	}

	return &ListTagsResponse{
		Tags:       tags,
		TotalCount: result.Count,
		Page:       page,
		PageSize:   pageSize,
	}, nil
}

// Docker Hub API response types

type dockerHubReposResponse struct {
	Count   int                  `json:"count"`
	Results []dockerHubRepoEntry `json:"results"`
}

type dockerHubRepoEntry struct {
	Name        string `json:"name"`
	Namespace   string `json:"namespace"`
	Description string `json:"description"`
	IsPrivate   bool   `json:"is_private"`
	PullCount   int64  `json:"pull_count"`
	LastUpdated string `json:"last_updated"`
}

type dockerHubTagsResponse struct {
	Count   int                 `json:"count"`
	Results []dockerHubTagEntry `json:"results"`
}

type dockerHubTagEntry struct {
	Name        string              `json:"name"`
	Digest      string              `json:"digest"`
	LastUpdated string              `json:"last_updated"`
	Images      []dockerHubTagImage `json:"images"`
}

type dockerHubTagImage struct {
	Architecture string `json:"architecture"`
	Digest       string `json:"digest"`
	Size         int64  `json:"size"`
}

// Helper functions

func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

type jsonReaderStruct struct {
	data []byte
	pos  int
}

func jsonReader(data []byte) io.Reader {
	return &jsonReaderStruct{data: data}
}

func (r *jsonReaderStruct) Read(p []byte) (n int, err error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n = copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}
