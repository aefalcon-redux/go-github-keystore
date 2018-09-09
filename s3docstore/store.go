package s3docstore

import (
	"bytes"
	"io/ioutil"
	"log"
	"path"
	"time"

	"github.com/aefalcon-redux/github-keystore-protobuf/go/appkeypb"
	"github.com/aefalcon-redux/go-github-keystore/docstore"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/golang/protobuf/proto"
)

type S3DocStore struct {
	Client   *s3.S3
	Location appkeypb.S3Ref
}

var _ docstore.DocStore = &S3DocStore{}

func NewS3DocStore(loc *appkeypb.Location) (*S3DocStore, error) {
	loc_s3loc, ok := loc.Location.(*appkeypb.Location_S3)
	if !ok {
		return nil, (*docstore.UnsupportedLocation)(loc)
	}
	sess := session.Must(session.NewSession())
	client := s3.New(sess, aws.NewConfig().WithRegion(loc_s3loc.S3.Region))
	return &S3DocStore{
		Client:   client,
		Location: *loc_s3loc.S3,
	}, nil
}

func (s *S3DocStore) DocKey(name string) string {
	return path.Join(s.Location.Key, name)
}

func (s *S3DocStore) GetDocument(name string, pb proto.Message) (*docstore.CacheMeta, error) {
	content, meta, err := s.GetDocumentRaw(name)
	err = proto.Unmarshal(content, pb)
	if err != nil {
		log.Printf("Unable to unmarshal index: %s", err)
		return nil, err
	}
	return meta, nil
}

func (s *S3DocStore) GetDocumentRaw(name string) ([]byte, *docstore.CacheMeta, error) {
	key := s.DocKey(name)
	getInput := s3.GetObjectInput{
		Bucket: &s.Location.Bucket,
		Key:    &key,
	}
	result, err := s.Client.GetObject(&getInput)
	if err != nil {
		log.Fatalf("Unable to get index: %s", err)
		return nil, nil, err
	}
	defer result.Body.Close()
	content, err := ioutil.ReadAll(result.Body)
	if err != nil {
		log.Printf("Unable to read index: %s", err)
		return nil, nil, err
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
			log.Printf("Failed to parse Expires as RFC1123, trying RFC1123Z")
			cacheMeta.Expires, err = time.Parse(time.RFC1123Z, *result.Expires)
		}
		if err != nil {
			log.Printf("Failed to parse Expires as RFC1123Z")
		}
	}
	if result.LastModified != nil {
		cacheMeta.LastModified = *result.LastModified
	}
	return content, &cacheMeta, nil
}

func (s *S3DocStore) PutDocument(name string, pb proto.Message) (*docstore.CacheMeta, error) {
	content, err := proto.Marshal(pb)
	if err != nil {
		log.Fatalf("Unable to marshal %T: %s", pb, err)
		return nil, err
	}
	return s.PutDocumentRaw(name, content)
}

func (s *S3DocStore) PutDocumentRaw(name string, content []byte) (*docstore.CacheMeta, error) {
	key := s.DocKey(name)
	putInput := s3.PutObjectInput{
		Bucket: &s.Location.Bucket,
		Key:    &key,
		Body:   bytes.NewReader(content),
	}
	result, err := s.Client.PutObject(&putInput)
	if err != nil {
		log.Printf("Unable to get index: %s", err)
		return nil, err
	}
	var cacheMeta docstore.CacheMeta
	if result.ETag != nil {
		cacheMeta.ETag = *result.ETag
	}
	return &cacheMeta, err
}

func (s *S3DocStore) DeleteDocument(name string) (*docstore.CacheMeta, error) {
	key := s.DocKey(name)
	input := s3.DeleteObjectInput{
		Bucket: &s.Location.Bucket,
		Key:    &key,
	}
	_, err := s.Client.DeleteObject(&input)
	if err != nil {
		log.Printf("Unable to get index: %s", err)
		return nil, err
	}
	return nil, err
}