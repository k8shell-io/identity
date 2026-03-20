// Copyright 2025 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package api provides gRPC client types and helpers for communicating with
// the k8Shell Identity service and its pluggable identity providers.
package api

import (
	"context"
	"encoding/json"

	"github.com/k8shell-io/common/pkg/gapi"
	"github.com/k8shell-io/common/pkg/models"
	"github.com/k8shell-io/identity/pkg/api/identitypb"
	"github.com/k8shell-io/identity/pkg/api/idppb"
	"github.com/k8shell-io/identity/pkg/api/typespb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// IdentityClient is a gRPC client for the Identity service.
type IdentityClient struct {
	identitypb.IdentityServiceClient
	client *gapi.Client
}

// NewIdentityClient creates a new IdentityClient from the provided configuration.
func NewIdentityClient(cfg gapi.ClientConfig) (*IdentityClient, error) {
	gapiClient, err := gapi.NewClient(cfg)
	if err != nil {
		return nil, err
	}
	return &IdentityClient{
		IdentityServiceClient: identitypb.NewIdentityServiceClient(gapiClient.Conn),
		client:                gapiClient,
	}, nil
}

// Close closes the underlying gRPC connection.
func (c *IdentityClient) Close() error {
	return c.client.Close()
}

// IdpClient is the interface that represents a connected identity provider.
// It extends the gRPC IdentityProviderServiceClient with provider metadata accessors.
type IdpClient interface {
	Name() string
	Capabilities() []string
	UserMaxAge() uint32
	Address() string
	Close() error
	idppb.IdentityProviderServiceClient
}

type idpClient struct {
	idppb.IdentityProviderServiceClient
	client *gapi.Client

	name         string
	capabilities []string
	userMaxAge   uint32
	address      string
}

func (c *idpClient) Close() error { return c.client.Close() }

func (c *idpClient) Name() string           { return c.name }
func (c *idpClient) Capabilities() []string { return c.capabilities }
func (c *idpClient) UserMaxAge() uint32     { return c.userMaxAge }
func (c *idpClient) Address() string        { return c.address }

// NewIdpClient creates a new IdpClient by connecting to the remote identity provider
// at the address specified in cfg and fetching its provider metadata.
func NewIdpClient(cfg gapi.ClientConfig) (IdpClient, error) {
	gapiClient, err := gapi.NewClient(cfg)
	if err != nil {
		return nil, err
	}

	c := &idpClient{
		IdentityProviderServiceClient: idppb.NewIdentityProviderServiceClient(gapiClient.Conn),
		client:                        gapiClient,
	}

	info, err := c.ProviderInfo(context.Background(), &idppb.ProviderInfoRequest{})
	if err != nil {
		_ = gapiClient.Close()
		return nil, err
	}

	c.name = info.Name
	c.capabilities = info.Capabilities
	c.userMaxAge = info.UserMaxAge
	c.address = info.Address

	return c, nil
}

// BlueprintProtoToCustomBlueprint converts a Blueprint protobuf message to a CustomBlueprint model.
func BlueprintProtoToCustomBlueprint(bp *typespb.Blueprint) (*models.CustomBlueprint, error) {
	if bp == nil {
		return nil, nil
	}
	var customBlueprint models.CustomBlueprint
	err := json.Unmarshal([]byte(bp.BlueprintJson), &customBlueprint)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Failed to parse custom blueprint JSON: %v", err)
	}
	return &customBlueprint, nil
}
