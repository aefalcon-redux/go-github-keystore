package messagestore

import (
	"fmt"
	"time"

	"github.com/aefalcon/github-keystore-protobuf/go/locationpb"
)

type CacheMeta struct {
	CacheControl string
	ETag         string
	Expires      time.Time
	LastModified time.Time
}

type UnsupportedLocation locationpb.Location

func (e *UnsupportedLocation) Error() string {
	return fmt.Sprintf("Ref type %T is not supported", (*locationpb.Location)(e))
}

type BlobStore interface {
	GetBlob(name string) ([]byte, *CacheMeta, error)
	PutBlob(name string, content []byte) (*CacheMeta, error)
	DeleteBlob(name string) (*CacheMeta, error)
}
