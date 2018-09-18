package main

import (
	"bytes"
	"context"
	"log"
	"os"

	"github.com/aefalcon/github-keystore-protobuf/go/locationpb"
	"github.com/aefalcon/github-keystore-protobuf/go/tokenpb"
	"github.com/aefalcon/go-github-keystore/kslog"
	"github.com/aefalcon/go-github-keystore/lambdacall"
	"github.com/aefalcon/go-github-keystore/messagestore"
	"github.com/aefalcon/go-github-keystore/s3store"
	"github.com/aefalcon/go-github-keystore/tokenstore"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	lambdaService "github.com/aws/aws-sdk-go/service/lambda"
	"github.com/golang/protobuf/jsonpb"
)

type LambdaGetInstallTokenRequest struct {
	tokenpb.GetInstallTokenRequest
}

func (r *LambdaGetInstallTokenRequest) UnmarshalJSON(data []byte) error {
	dataReader := bytes.NewReader(data)
	return jsonpb.Unmarshal(dataReader, &r.GetInstallTokenRequest)
}

type LambdaGetInstallTokenResponse struct {
	tokenpb.GetInstallTokenResponse
}

func (r *LambdaGetInstallTokenResponse) MarshalJSON() ([]byte, error) {
	marshaler := jsonpb.Marshaler{}
	buffer := bytes.NewBuffer(nil)
	err := marshaler.Marshal(buffer, &r.GetInstallTokenResponse)
	if err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

type RequestHandler struct {
	Service *tokenstore.InstallTokenService
}

func (h *RequestHandler) HandleRequest(ctx context.Context, req *LambdaGetInstallTokenRequest) (*LambdaGetInstallTokenResponse, error) {
	logger := kslog.DefaultLogger{}
	reply, err := h.Service.GetInstallToken(&req.GetInstallTokenRequest, logger)
	if err != nil {
		return nil, err
	}
	resp := LambdaGetInstallTokenResponse{
		GetInstallTokenResponse: *reply,
	}
	return &resp, err
}

const (
	ENV_TOKEN_STORE_BUCKET = "TOKEN_STORE_BUCKET"
	ENV_TOKEN_STORE_PREFIX = "TOKEN_STORE_PREFIX"
	ENV_REGION             = "REGION"
	ENV_SIGN_JWT_FUNC      = "SIGN_JWT_APP"
)

func main() {
	var tokenStoreBucket, tokenStorePrefix, awsRegion, jwtFunc string
	ok := true
	envSpecs := []struct {
		envName  string
		varLoc   *string
		required bool
	}{
		{ENV_TOKEN_STORE_BUCKET, &tokenStoreBucket, true},
		{ENV_TOKEN_STORE_PREFIX, &tokenStorePrefix, false},
		{ENV_REGION, &awsRegion, true},
		{ENV_SIGN_JWT_FUNC, &jwtFunc, true},
	}
	for _, envSpec := range envSpecs {
		*envSpec.varLoc = os.Getenv(envSpec.envName)
		if envSpec.required && *envSpec.varLoc == "" {
			log.Printf("Missing environment variable %s", envSpec.envName)
			ok = false
		}
	}
	if !ok {
		log.Fatalf("Exiting due to missing environment variables")
	}
	location := locationpb.Location{
		Location: &locationpb.Location_S3{
			S3: &locationpb.S3Ref{
				Bucket: tokenStoreBucket,
				Key:    tokenStorePrefix,
				Region: awsRegion,
			},
		},
	}
	blobStore, err := s3store.NewS3BlobStore(&location)
	if err != nil {
		log.Fatalf("Failed to create store: %s", err)
	}
	messageStore := messagestore.BlobMessageStore{
		BlobStore: blobStore,
	}
	sess := session.Must(session.NewSession())
	signLambdaService := lambdaService.New(sess, aws.NewConfig().WithRegion(awsRegion))
	signingService := lambdacall.LambdaSigningService{
		Service:  signLambdaService,
		FuncName: jwtFunc,
	}
	service := tokenstore.InstallTokenService{
		TokenMessageStore:    tokenstore.NewTokenMessageStore(&messageStore, nil),
		SigningService:       &signingService,
		InstallTokenProvider: tokenstore.V3InstallTokenProvider,
	}
	handler := RequestHandler{
		Service: &service,
	}
	lambda.Start(handler.HandleRequest)
}
