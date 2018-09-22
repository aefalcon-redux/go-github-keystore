package s3store

import (
	"bytes"
	"io/ioutil"
	"path"
	"time"

	"github.com/aefalcon/github-keystore-protobuf/go/locationpb"
	"github.com/aefalcon/go-github-keystore/docstore"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
)

type S3BlobStore struct {
	Client   *s3.S3
	Location locationpb.S3Ref
}

var _ docstore.BlobStore = &S3BlobStore{}

func NewS3BlobStore(loc *locationpb.Location) (*S3BlobStore, error) {
	loc_s3loc, ok := loc.Location.(*locationpb.Location_S3)
	if !ok {
		return nil, (*docstore.UnsupportedLocation)(loc)
	}
	sess := session.Must(session.NewSession())
	client := s3.New(sess, aws.NewConfig().WithRegion(loc_s3loc.S3.Region))
	return &S3BlobStore{
		Client:   client,
		Location: *loc_s3loc.S3,
	}, nil
}

func (s *S3BlobStore) DocKey(name string) string {
	return path.Join(s.Location.Key, name)
}

func (s *S3BlobStore) GetDocumentRaw(name string) ([]byte, *docstore.CacheMeta, error) {
	key := s.DocKey(name)
	getInput := s3.GetObjectInput{
		Bucket: &s.Location.Bucket,
		Key:    &key,
	}
	result, err := s.Client.GetObject(&getInput)
	if err != nil {
		return nil, nil, err
	}
	defer result.Body.Close()
	content, err := ioutil.ReadAll(result.Body)
	if err != nil {
		wrapErr := docstore.ReadResourceError{
			Name:  name,
			Cause: err,
		}
		return nil, nil, &wrapErr
	}
	var cacheMeta docstore.CacheMeta
	if result.CacheControl != nil {
		cacheMeta.CacheControl = *result.CacheControl
	}
	if result.ETag != nil {
		cacheMeta.ETag = *result.ETag
	}
	if result.Expires != nil {
		cacheMeta.Expires, err = time.Parse(time.RFC1123, *result.Expires)
		if err != nil {
			cacheMeta.Expires, err = time.Parse(time.RFC1123Z, *result.Expires)
		}
	}
	if result.LastModified != nil {
		cacheMeta.LastModified = *result.LastModified
	}
	return content, &cacheMeta, nil
}

func (s *S3BlobStore) PutDocumentRaw(name string, content []byte) (*docstore.CacheMeta, error) {
	key := s.DocKey(name)
	putInput := s3.PutObjectInput{
		Bucket: &s.Location.Bucket,
		Key:    &key,
		Body:   bytes.NewReader(content),
	}
	result, err := s.Client.PutObject(&putInput)
	if err != nil {
		wrapErr := docstore.PutResourceError{
			Name:  name,
			Cause: err,
		}
		return nil, &wrapErr
	}
	var cacheMeta docstore.CacheMeta
	if result.ETag != nil {
		cacheMeta.ETag = *result.ETag
	}
	return &cacheMeta, err
}

func (s *S3BlobStore) DeleteDocument(name string) (*docstore.CacheMeta, error) {
	key := s.DocKey(name)
	input := s3.DeleteObjectInput{
		Bucket: &s.Location.Bucket,
		Key:    &key,
	}
	_, err := s.Client.DeleteObject(&input)
	if err != nil {
		wrapErr := docstore.DeleteResourceError{
			Name:  name,
			Cause: err,
		}
		return nil, &wrapErr
	}
	return nil, err
}
