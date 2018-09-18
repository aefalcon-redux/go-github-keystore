package docstore

import (
	"fmt"
	"time"

	"github.com/aefalcon/github-keystore-protobuf/go/appkeypb"
	"github.com/golang/protobuf/proto"
)

type NoSuchResource string

func (e NoSuchResource) Error() string {
	return fmt.Sprintf("resource %s does not exist", string(e))
}

type GetResourceError struct {
	Name  string
	Cause error
}

func (e *GetResourceError) Error() string {
	return fmt.Sprintf("failed to get resource %s: %s", e.Name, e.Cause)
}

type PutResourceError struct {
	Name  string
	Cause error
}

func (e *PutResourceError) Error() string {
	return fmt.Sprintf("failed to put resource %s: %s", e.Name, e.Cause)
}

type DeleteResourceError struct {
	Name  string
	Cause error
}

func (e *DeleteResourceError) Error() string {
	return fmt.Sprintf("failed to delete resource %s: %s", e.Name, e.Cause)
}

type DecodeResourceError struct {
	Name  string
	Cause error
}

func (e *DecodeResourceError) Error() string {
	return fmt.Sprintf("failed to decode resource %s: %s", e.Name, e.Cause)
}

type EncodeResourceError struct {
	Name  string
	Cause error
}

func (e *EncodeResourceError) Error() string {
	return fmt.Sprintf("failed to encode resource %s: %s", e.Name, e.Cause)
}

type ReadResourceError struct {
	Name  string
	Cause error
}

func (e *ReadResourceError) Error() string {
	return fmt.Sprintf("failed to decode resource %s: %s", e.Name, e.Cause)
}

type CacheMeta struct {
	CacheControl string
	ETag         string
	Expires      time.Time
	LastModified time.Time
}

type UnsupportedLocation appkeypb.Location

func (e *UnsupportedLocation) Error() string {
	return fmt.Sprintf("Ref type %T is not supported", (*appkeypb.Location)(e))
}

type BlobStore interface {
	GetDocumentRaw(name string) ([]byte, *CacheMeta, error)
	PutDocumentRaw(name string, content []byte) (*CacheMeta, error)
	DeleteDocument(name string) (*CacheMeta, error)
}

type DocStore interface {
	BlobStore
	GetDocument(name string, pb proto.Message) (*CacheMeta, error)
	PutDocument(name string, pb proto.Message) (*CacheMeta, error)
}

type BlobDocStore struct {
	BlobStore
}

func (s *BlobDocStore) GetDocument(name string, pb proto.Message) (*CacheMeta, error) {
	content, meta, err := s.GetDocumentRaw(name)
	if err != nil {
		wrapErr := GetResourceError{
			Name:  name,
			Cause: err,
		}
		return nil, &wrapErr
	}
	err = proto.Unmarshal(content, pb)
	if err != nil {
		wrapErr := DecodeResourceError{
			Name:  name,
			Cause: err,
		}
		return nil, &wrapErr
	}
	return meta, nil
}

func (s *BlobDocStore) PutDocument(name string, pb proto.Message) (*CacheMeta, error) {
	content, err := proto.Marshal(pb)
	if err != nil {
		wrapErr := EncodeResourceError{
			Name:  name,
			Cause: err,
		}
		return nil, &wrapErr
	}
	return s.PutDocumentRaw(name, content)
}
