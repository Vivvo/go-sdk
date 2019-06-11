package utils

import (
	"io"
	"log"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
)

type SpaceConfig struct {
	S3Session *session.Session
	Bucket    string
}

// NewS3Instance creates a new S3 instance with the specifed endpoint & region.
// It requires a Client Key & Secret
func NewS3Session(endpoint, region, key, secret string) *session.Session {
	s3Config := &aws.Config{
		Credentials: credentials.NewStaticCredentials(key, secret, ""),
		Endpoint:    aws.String(endpoint),
		Region:      aws.String(region), // This is counter intuitive, but it will fail with a non-AWS region name.
	}
	return session.Must(session.NewSession(s3Config))
}

// Upload will upload the content with the specifed key to the specifed bucket
func (s *SpaceConfig) Upload(content io.Reader, key string) error {

	uploader := s3manager.NewUploader(s.S3Session)

	object := &s3manager.UploadInput{
		Body:   content,
		Bucket: aws.String(s.Bucket),
		Key:    aws.String(key),
	}
	_, err := uploader.Upload(object)
	if err != nil {
		log.Println(err)
		return err
	}
	return nil
}
