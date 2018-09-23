package lambdacall

import (
	"fmt"

	"github.com/aefalcon/github-keystore-protobuf/go/appkeypb"
	"github.com/aefalcon/go-github-keystore/kslog"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/golang/protobuf/jsonpb"
	"github.com/golang/protobuf/proto"
)

func CallPbLambda(svc *lambda.Lambda, funcName string, in, out proto.Message) error {
	marshaler := jsonpb.Marshaler{}
	reqDoc, err := marshaler.MarshalToString(in)
	if err != nil {
		return err
	}
	invokeInput := lambda.InvokeInput{
		FunctionName: &funcName,
		Payload:      []byte(reqDoc),
	}
	invokeOutput, err := svc.Invoke(&invokeInput)
	if err != nil {
		return err
	}
	err = jsonpb.UnmarshalString(string(invokeOutput.Payload), out)
	if err != nil {
		return fmt.Errorf("Failed to unmarshal %s: %s", string(invokeOutput.Payload), err)
	}
	return nil
}

type LambdaSigningService struct {
	Service  *lambda.Lambda
	FuncName string
}

func (s *LambdaSigningService) SignJwt(req *appkeypb.SignJwtRequest, logger kslog.KsLogger) (*appkeypb.SignJwtResponse, error) {
	var resp appkeypb.SignJwtResponse
	err := CallPbLambda(s.Service, s.FuncName, req, &resp)
	return &resp, err
}
