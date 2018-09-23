package messagestore

import (
	"github.com/golang/protobuf/proto"
)

type MessageStore interface {
	GetMessage(name string, pb proto.Message) (*CacheMeta, error)
	PutMessage(name string, pb proto.Message) (*CacheMeta, error)
	DeleteMessage(name string) (*CacheMeta, error)
}

type BlobMessageStore struct {
	BlobStore
}

func (s *BlobMessageStore) GetMessage(name string, pb proto.Message) (*CacheMeta, error) {
	content, meta, err := s.GetBlob(name)
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

func (s *BlobMessageStore) PutMessage(name string, pb proto.Message) (*CacheMeta, error) {
	content, err := proto.Marshal(pb)
	if err != nil {
		wrapErr := EncodeResourceError{
			Name:  name,
			Cause: err,
		}
		return nil, &wrapErr
	}
	return s.PutBlob(name, content)
}

func (s *BlobMessageStore) DeleteMessage(name string) (*CacheMeta, error) {
	return s.DeleteBlob(name)
}
