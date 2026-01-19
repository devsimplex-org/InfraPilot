package registry

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
)

// ECRClient implements the Client interface for AWS ECR
type ECRClient struct {
	accessKeyID     string
	secretAccessKey string
	region          string
	accountID       string
	client          *ecr.Client
}

// NewECRClient creates a new ECR client
func NewECRClient(accessKeyID, secretAccessKey, region, accountID string) *ECRClient {
	return &ECRClient{
		accessKeyID:     accessKeyID,
		secretAccessKey: secretAccessKey,
		region:          region,
		accountID:       accountID,
	}
}

// getClient lazily initializes the ECR client
func (c *ECRClient) getClient(ctx context.Context) (*ecr.Client, error) {
	if c.client != nil {
		return c.client, nil
	}

	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(c.region),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
			c.accessKeyID,
			c.secretAccessKey,
			"",
		)),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	c.client = ecr.NewFromConfig(cfg)
	return c.client, nil
}

// TestConnection tests the connection to ECR
func (c *ECRClient) TestConnection(ctx context.Context) error {
	client, err := c.getClient(ctx)
	if err != nil {
		return err
	}

	// Try to describe repositories (limited to 1) to test the connection
	_, err = client.DescribeRepositories(ctx, &ecr.DescribeRepositoriesInput{
		MaxResults: aws.Int32(1),
	})
	if err != nil {
		return fmt.Errorf("failed to connect to ECR: %w", err)
	}

	return nil
}

// ListRepositories lists ECR repositories with pagination
func (c *ECRClient) ListRepositories(ctx context.Context, page, pageSize int) (*ListRepositoriesResponse, error) {
	client, err := c.getClient(ctx)
	if err != nil {
		return nil, err
	}

	// ECR uses token-based pagination, so we need to iterate to get to the right page
	var nextToken *string
	var repos []Repository
	currentPage := 0

	for {
		input := &ecr.DescribeRepositoriesInput{
			MaxResults: aws.Int32(int32(pageSize)),
			NextToken:  nextToken,
		}

		output, err := client.DescribeRepositories(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("failed to list repositories: %w", err)
		}

		currentPage++

		if currentPage == page {
			// Convert to our Repository type
			for _, repo := range output.Repositories {
				var desc *string
				if repo.RepositoryUri != nil {
					desc = repo.RepositoryUri
				}

				repos = append(repos, Repository{
					Name:        aws.ToString(repo.RepositoryName),
					FullName:    aws.ToString(repo.RepositoryUri),
					Description: desc,
					IsPrivate:   true, // ECR repos are always private
					PullCount:   0,    // ECR doesn't expose pull count
				})
			}
			break
		}

		nextToken = output.NextToken
		if nextToken == nil {
			break
		}
	}

	return &ListRepositoriesResponse{
		Repositories: repos,
		TotalCount:   len(repos), // ECR doesn't provide total count
		Page:         page,
		PageSize:     pageSize,
	}, nil
}

// ListTags lists tags for an ECR repository
func (c *ECRClient) ListTags(ctx context.Context, repository string, page, pageSize int) (*ListTagsResponse, error) {
	client, err := c.getClient(ctx)
	if err != nil {
		return nil, err
	}

	// ECR uses token-based pagination
	var nextToken *string
	var tags []Tag
	currentPage := 0

	for {
		input := &ecr.DescribeImagesInput{
			RepositoryName: aws.String(repository),
			MaxResults:     aws.Int32(int32(pageSize)),
			NextToken:      nextToken,
		}

		output, err := client.DescribeImages(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("failed to list images: %w", err)
		}

		currentPage++

		if currentPage == page {
			for _, image := range output.ImageDetails {
				// An image can have multiple tags
				for _, tag := range image.ImageTags {
					var pushedAt *string
					if image.ImagePushedAt != nil {
						t := image.ImagePushedAt.Format("2006-01-02T15:04:05Z")
						pushedAt = &t
					}

					tags = append(tags, Tag{
						Name:      tag,
						Digest:    image.ImageDigest,
						SizeBytes: aws.ToInt64(image.ImageSizeInBytes),
						PushedAt:  pushedAt,
					})
				}
			}
			break
		}

		nextToken = output.NextToken
		if nextToken == nil {
			break
		}
	}

	return &ListTagsResponse{
		Tags:       tags,
		TotalCount: len(tags),
		Page:       page,
		PageSize:   pageSize,
	}, nil
}

// Provider returns the provider type
func (c *ECRClient) Provider() Provider {
	return ProviderECR
}
