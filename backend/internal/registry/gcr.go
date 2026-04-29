package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// GCRClient implements the Client interface for Google Container Registry / Artifact Registry
type GCRClient struct {
	serviceAccountJSON string
	projectID          string
	httpClient         *http.Client
}

// NewGCRClient creates a new GCR client
func NewGCRClient(serviceAccountJSON, projectID string) *GCRClient {
	return &GCRClient{
		serviceAccountJSON: serviceAccountJSON,
		projectID:          projectID,
	}
}

// getHTTPClient lazily initializes an authenticated HTTP client
func (c *GCRClient) getHTTPClient(ctx context.Context) (*http.Client, error) {
	if c.httpClient != nil {
		return c.httpClient, nil
	}

	creds, err := google.CredentialsFromJSON(ctx, []byte(c.serviceAccountJSON),
		"https://www.googleapis.com/auth/cloud-platform",
	)
	if err != nil {
		return nil, fmt.Errorf("failed to parse service account JSON: %w", err)
	}

	c.httpClient = oauth2.NewClient(ctx, creds.TokenSource)
	return c.httpClient, nil
}

// TestConnection tests the connection to GCR/Artifact Registry
func (c *GCRClient) TestConnection(ctx context.Context) error {
	client, err := c.getHTTPClient(ctx)
	if err != nil {
		return err
	}

	// Try to list repositories (limited) to test the connection
	// Using Artifact Registry API
	url := fmt.Sprintf("https://artifactregistry.googleapis.com/v1/projects/%s/locations/-/repositories?pageSize=1", c.projectID)

	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("failed to connect to GCR: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to connect to GCR: %s - %s", resp.Status, string(body))
	}

	return nil
}

// gcrListReposResponse represents the Artifact Registry list repositories response
type gcrListReposResponse struct {
	Repositories []struct {
		Name        string `json:"name"`
		Format      string `json:"format"`
		Description string `json:"description"`
		CreateTime  string `json:"createTime"`
		UpdateTime  string `json:"updateTime"`
	} `json:"repositories"`
	NextPageToken string `json:"nextPageToken"`
}

// ListRepositories lists GCR/Artifact Registry repositories with pagination
func (c *GCRClient) ListRepositories(ctx context.Context, page, pageSize int) (*ListRepositoriesResponse, error) {
	client, err := c.getHTTPClient(ctx)
	if err != nil {
		return nil, err
	}

	// Using Artifact Registry API
	url := fmt.Sprintf("https://artifactregistry.googleapis.com/v1/projects/%s/locations/-/repositories?pageSize=%d", c.projectID, pageSize)

	// Handle pagination by iterating through pages
	var pageToken string
	currentPage := 1

	for currentPage < page {
		reqURL := url
		if pageToken != "" {
			reqURL += "&pageToken=" + pageToken
		}

		resp, err := client.Get(reqURL)
		if err != nil {
			return nil, fmt.Errorf("failed to list repositories: %w", err)
		}
		defer resp.Body.Close()

		var result gcrListReposResponse
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return nil, fmt.Errorf("failed to decode response: %w", err)
		}

		if result.NextPageToken == "" {
			break
		}
		pageToken = result.NextPageToken
		currentPage++
	}

	// Now fetch the actual page we want
	reqURL := url
	if pageToken != "" {
		reqURL += "&pageToken=" + pageToken
	}

	resp, err := client.Get(reqURL)
	if err != nil {
		return nil, fmt.Errorf("failed to list repositories: %w", err)
	}
	defer resp.Body.Close()

	var result gcrListReposResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	var repos []Repository
	for _, repo := range result.Repositories {
		// Only include Docker format repositories
		if repo.Format != "DOCKER" {
			continue
		}

		var desc *string
		if repo.Description != "" {
			desc = &repo.Description
		}

		repos = append(repos, Repository{
			Name:        repo.Name,
			FullName:    repo.Name,
			Description: desc,
			IsPrivate:   true, // GCR repos are private by default
			PullCount:   0,    // Not available in Artifact Registry API
			UpdatedAt:   &repo.UpdateTime,
		})
	}

	return &ListRepositoriesResponse{
		Repositories: repos,
		TotalCount:   len(repos),
		Page:         page,
		PageSize:     pageSize,
	}, nil
}

// gcrListTagsResponse represents the Artifact Registry list tags response
type gcrListTagsResponse struct {
	Tags []struct {
		Name       string `json:"name"`
		Version    string `json:"version"`
		CreateTime string `json:"createTime"`
	} `json:"tags"`
	NextPageToken string `json:"nextPageToken"`
}

// gcrVersionResponse represents the Artifact Registry version info
type gcrVersionResponse struct {
	Name       string `json:"name"`
	CreateTime string `json:"createTime"`
	Metadata   struct {
		ImageSizeBytes string `json:"imageSizeBytes"`
	} `json:"metadata"`
}

// ListTags lists tags for a GCR/Artifact Registry repository
func (c *GCRClient) ListTags(ctx context.Context, repository string, page, pageSize int) (*ListTagsResponse, error) {
	client, err := c.getHTTPClient(ctx)
	if err != nil {
		return nil, err
	}

	// Using Artifact Registry API to list versions/tags
	url := fmt.Sprintf("https://artifactregistry.googleapis.com/v1/%s/packages/-/versions?pageSize=%d", repository, pageSize)

	// Handle pagination
	var pageToken string
	currentPage := 1

	for currentPage < page {
		reqURL := url
		if pageToken != "" {
			reqURL += "&pageToken=" + pageToken
		}

		resp, err := client.Get(reqURL)
		if err != nil {
			return nil, fmt.Errorf("failed to list tags: %w", err)
		}

		var result struct {
			Versions      []gcrVersionResponse `json:"versions"`
			NextPageToken string               `json:"nextPageToken"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			resp.Body.Close()
			return nil, fmt.Errorf("failed to decode response: %w", err)
		}
		resp.Body.Close()

		if result.NextPageToken == "" {
			break
		}
		pageToken = result.NextPageToken
		currentPage++
	}

	// Fetch the actual page
	reqURL := url
	if pageToken != "" {
		reqURL += "&pageToken=" + pageToken
	}

	resp, err := client.Get(reqURL)
	if err != nil {
		return nil, fmt.Errorf("failed to list tags: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Versions      []gcrVersionResponse `json:"versions"`
		NextPageToken string               `json:"nextPageToken"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	var tags []Tag
	for _, version := range result.Versions {
		var sizeBytes int64
		if version.Metadata.ImageSizeBytes != "" {
			fmt.Sscanf(version.Metadata.ImageSizeBytes, "%d", &sizeBytes)
		}

		// Parse create time
		var pushedAt *string
		if version.CreateTime != "" {
			if t, err := time.Parse(time.RFC3339, version.CreateTime); err == nil {
				formatted := t.Format("2006-01-02T15:04:05Z")
				pushedAt = &formatted
			}
		}

		tags = append(tags, Tag{
			Name:      version.Name,
			Digest:    nil, // Would need to fetch separately
			SizeBytes: sizeBytes,
			PushedAt:  pushedAt,
		})
	}

	return &ListTagsResponse{
		Tags:       tags,
		TotalCount: len(tags),
		Page:       page,
		PageSize:   pageSize,
	}, nil
}

// Provider returns the provider type
func (c *GCRClient) Provider() Provider {
	return ProviderGCR
}
