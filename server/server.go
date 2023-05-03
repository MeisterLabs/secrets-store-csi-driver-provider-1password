// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package server implements a grpc server to receive mount events
package server

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"hash/crc32"

	"github.com/martyn-meister/secrets-store-csi-driver-provider-1password/config"

	spb "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"
	"k8s.io/klog/v2"
	"sigs.k8s.io/secrets-store-csi-driver/provider/v1alpha1"
)

//TODO: implement this better, elsewhere.  copied here so we can move forward quickly.
type SecretPayload struct {

	// The secret data. Must be no larger than 64KiB.
	Data []byte `protobuf:"bytes,1,opt,name=data,proto3" json:"data,omitempty"`
	// Optional. If specified,
	// [SecretManagerService][google.cloud.secretmanager.v1.SecretManagerService]
	// will verify the integrity of the received
	// [data][google.cloud.secretmanager.v1.SecretPayload.data] on
	// [SecretManagerService.AddSecretVersion][google.cloud.secretmanager.v1.SecretManagerService.AddSecretVersion]
	// calls using the crc32c checksum and store it to include in future
	// [SecretManagerService.AccessSecretVersion][google.cloud.secretmanager.v1.SecretManagerService.AccessSecretVersion]
	// responses. If a checksum is not provided in the
	// [SecretManagerService.AddSecretVersion][google.cloud.secretmanager.v1.SecretManagerService.AddSecretVersion]
	// request, the
	// [SecretManagerService][google.cloud.secretmanager.v1.SecretManagerService]
	// will generate and store one for you.
	//
	// The CRC32C value is encoded as a Int64 for compatibility, and can be
	// safely downconverted to uint32 in languages that support this type.
	// https://cloud.google.com/apis/design/design_patterns#integer_types
	DataCrc32C *int64 `protobuf:"varint,2,opt,name=data_crc32c,json=dataCrc32c,proto3,oneof" json:"data_crc32c,omitempty"`
	// contains filtered or unexported fields
}

//TODO: implement this better, elsewhere.  copied here so we can move forward quickly.
type AccessSecretVersionResponse struct {

	// The resource name of the [SecretVersion][google.cloud.secretmanager.v1.SecretVersion] in the format
	// `projects/*/secrets/*/versions/*`.
	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	// Secret payload
	Payload *SecretPayload `protobuf:"bytes,2,opt,name=payload,proto3" json:"payload,omitempty"`
	// contains filtered or unexported fields
}

func (x *AccessSecretVersionResponse) GetName() string {
	return "fake"
}

func (x *AccessSecretVersionResponse) GetPayload() *SecretPayload {
	s, _ := fakeSecret()
	return &s
}

type Server struct {
	RuntimeVersion string
}

var _ v1alpha1.CSIDriverProviderServer = &Server{}

// Mount implements provider csi-provider method
func (s *Server) Mount(ctx context.Context, req *v1alpha1.MountRequest) (*v1alpha1.MountResponse, error) {
	p, err := strconv.ParseUint(req.GetPermission(), 10, 32)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, fmt.Sprintf("Unable to parse permissions: %s", req.GetPermission()))

	}

	params := &config.MountParams{
		Attributes:  req.GetAttributes(),
		KubeSecrets: req.GetSecrets(),
		TargetPath:  req.GetTargetPath(),
		Permissions: os.FileMode(p),
	}

	cfg, err := config.Parse(params)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	// Fetch the secrets from the secretmanager API based on the
	// SecretProviderClass configuration.
	return handleMountEvent(ctx, 0, nil, cfg)
}

// Version implements provider csi-provider method
func (s *Server) Version(ctx context.Context, req *v1alpha1.VersionRequest) (*v1alpha1.VersionResponse, error) {
	return &v1alpha1.VersionResponse{
		Version:        "v1alpha1",
		RuntimeName:    "secrets-store-csi-driver-provider-1password",
		RuntimeVersion: s.RuntimeVersion,
	}, nil
}

func fakeSecretResponse() (AccessSecretVersionResponse, error) {
	p, _ := fakeSecret()
	resp := AccessSecretVersionResponse{Name:"fake",Payload: &p}
    return resp, nil
}

func fakeSecret() (SecretPayload, error) {
	secret := SecretPayload{}
	secret.Data = []byte("XYZZY")
	var crc int64
	crc = int64(crc32.Checksum(secret.Data, crc32.IEEETable))
    secret.DataCrc32C = &crc
	return secret, nil
}

func fakeSecretsList() []SecretPayload {
	s,_ := fakeSecret()
	list := []SecretPayload {s}
	return list
}

// handleMountEvent fetches the secrets from the secretmanager API and
// include them in the MountResponse based on the SecretProviderClass
// configuration.
//TODO: removed was secretclient, remove this from the signature later.
func handleMountEvent(ctx context.Context, removed int, creds credentials.PerRPCCredentials, cfg *config.MountConfig) (*v1alpha1.MountResponse, error) {
	results := make([]*AccessSecretVersionResponse, len(cfg.Secrets))
	errs := make([]error, len(cfg.Secrets))

	// In parallel fetch all secrets needed for the mount
	wg := sync.WaitGroup{}
	for i, _ := range cfg.Secrets {
		wg.Add(1)

		i := i
		go func() {
			defer wg.Done()
			resp, err := fakeSecretResponse()
			klog.InfoS("\"fetched\" a secret", "response", resp)
			results[i] = &resp
			errs[i] = err
		}()
	}
	wg.Wait()

	klog.InfoS("\"fetched\" all secrets", "resource_name", results, "pod", klog.ObjectRef{Namespace: cfg.PodInfo.Namespace, Name: cfg.PodInfo.Name})
	// If any access failed, return a grpc status error that includes each
	// individual status error in the Details field.
	//
	// If there are any failures then there will be no changes to the
	// filesystem. Initial mount events will fail (preventing pod start) and
	// the secrets-store-csi-driver will emit pod events on rotation failures.
	// By erroring out on any failures we prevent partial rotations (i.e. the
	// username file was updated to a new value but the corresponding password
	// field was not).
	if err := buildErr(errs); err != nil {
		return nil, err
	}

	out := &v1alpha1.MountResponse{}

	// Add secrets to response.
	ovs := make([]*v1alpha1.ObjectVersion, len(cfg.Secrets))
	for i, secret := range cfg.Secrets {
		mode := int32(cfg.Permissions)
		if secret.Mode != nil {
			mode = *secret.Mode
		}

		result := results[i]
		out.Files = append(out.Files, &v1alpha1.File{
			Path:     secret.PathString(),
			Mode:     mode,
			Contents: result.Payload.Data,
		})
		klog.V(5).InfoS("added secret to response", "resource_name", secret.ResourceName, "file_name", secret.FileName, "pod", klog.ObjectRef{Namespace: cfg.PodInfo.Namespace, Name: cfg.PodInfo.Name})

		ovs[i] = &v1alpha1.ObjectVersion{
			Id:      secret.ResourceName,
			Version: result.GetName(),
		}
	}
	out.ObjectVersion = ovs

	return out, nil
}

// buildErr consolidates many errors into a single Status protobuf error message
// with each individual error included into the status Details any proto. The
// consolidated proto is converted to a general error.
func buildErr(errs []error) error {
	msgs := make([]string, 0, len(errs))
	hasErr := false
	s := &spb.Status{
		Code:    int32(codes.Internal),
		Details: make([]*anypb.Any, 0),
	}

	for i := range errs {
		if errs[i] == nil {
			continue
		}
		hasErr = true
		msgs = append(msgs, errs[i].Error())

		any, _ := anypb.New(status.Convert(errs[i]).Proto())
		s.Details = append(s.Details, any)
	}
	if !hasErr {
		return nil
	}
	s.Message = strings.Join(msgs, ",")
	return status.FromProto(s).Err()
}
