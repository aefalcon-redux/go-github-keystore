package main

import (
	"bytes"
	"context"
	"log"
	"os"

	"github.com/aefalcon/github-keystore-protobuf/go/appkeypb"
	"github.com/aefalcon/github-keystore-protobuf/go/locationpb"
	"github.com/aefalcon/go-github-keystore/appkeystore"
	"github.com/aefalcon/go-github-keystore/docstore"
	"github.com/aefalcon/go-github-keystore/kslog"
	"github.com/aefalcon/go-github-keystore/s3store"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/golang/protobuf/jsonpb"
)

type LambdaSignJwtRequest struct {
	appkeypb.SignJwtRequest
}

func (r *LambdaSignJwtRequest) UnmarshalJSON(data []byte) error {
	dataReader := bytes.NewReader(data)
	return jsonpb.Unmarshal(dataReader, &r.SignJwtRequest)
}

func HandleRequest(store *appkeystore.AppKeyStore, ctx context.Context, req *LambdaSignJwtRequest) (string, error) {
	logger := kslog.DefaultLogger{}
	reply, err := store.SignJwt(&req.SignJwtRequest, logger)
	if err != nil {
		return "", err
	}
	marshaler := jsonpb.Marshaler{}
	return marshaler.MarshalToString(reply)
}

func main() {
	storeBucket := os.Getenv("STORE_BUCKET")
	storePrefix := os.Getenv("STORE_PREFIX")
	storeRegion := os.Getenv("STORE_REGION")
	location := locationpb.Location{
		Location: &locationpb.Location_S3{
			S3: &locationpb.S3Ref{
				Bucket: storeBucket,
				Key:    storePrefix,
				Region: storeRegion,
			},
		},
	}
	blobStore, err := s3store.NewS3BlobStore(&location)
	if err != nil {
		log.Fatalf("Failed to create store: %s", err)
	}
	docStore := docstore.BlobDocStore{
		BlobStore: blobStore,
	}
	keyStore := appkeystore.NewAppKeyStore(&docStore, nil)
	handleFunc := func(ctx context.Context, req *LambdaSignJwtRequest) (string, error) {
		return HandleRequest(keyStore, ctx, req)
	}
	lambda.Start(handleFunc)
}
