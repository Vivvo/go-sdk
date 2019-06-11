package utils

import (
	"log"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
)

type SpaceConfig struct {
	S3Instance *s3.S3
	Bucket     string
}

// NewS3Instance creates a new S3 instance with the specifed endpoint & region.
// It requires a Client Key & Secret
func NewS3Instance(endpoint, region, key, secret string) *s3.S3 {
	s3Config := &aws.Config{
		Credentials: credentials.NewStaticCredentials(key, secret, ""),
		Endpoint:    aws.String(endpoint),
		Region:      aws.String(region), // This is counter intuitive, but it will fail with a non-AWS region name.
	}
	return s3.New(session.New(s3Config))
}

// ListBuckets will list all storage buckets
func (s *SpaceConfig) ListBuckets() ([]*s3.Bucket, error) {
	spaces, err := s.S3Instance.ListBuckets(nil)
	if err != nil {
		log.Println(err)
		return nil, err
	}
	return spaces.Buckets, nil
}

// Upload will upload the content with the specifed key to the specifed bucket
func (s *SpaceConfig) Upload(content, key string) error {
	object := s3.PutObjectInput{
		Body:   strings.NewReader(content),
		Bucket: aws.String(s.Bucket),
		Key:    aws.String(key),
	}
	_, err := s.S3Instance.PutObject(&object)
	if err != nil {
		log.Println(err)
		return err
	}
	return nil
}
