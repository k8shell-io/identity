// Copyright 2025 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package db provides database access and management for the k8Shell Identity service.
// It provides persistence for users and methods for managing them.
package db

import (
	"fmt"

	"github.com/k8shell-io/common/pkg/db"
	"github.com/k8shell-io/common/pkg/logger"
	"github.com/rs/zerolog"
)

// DB wraps the shared database implementation for the identity service.
type DB struct {
	db.DB
	autoCreateOrgs []string
	log            *zerolog.Logger
}

// NewDB creates a new DB for the identity service.
// autoCreateOrgs is the list of organization names that may be created automatically
// when a user with that organization is first seen. Use ["*"] to allow all organizations.
func NewDB(config db.DBConfig, autoCreateOrgs []string) (*DB, error) {
	d, err := db.NewDB(config, "identity")
	if err != nil {
		return nil, fmt.Errorf("create db: %w", err)
	}
	return &DB{
		DB:             *d,
		autoCreateOrgs: autoCreateOrgs,
		log:            logger.NewLogger("db")}, nil
}

// orgAutoCreateAllowed reports whether org may be created automatically.
func (d *DB) orgAutoCreateAllowed(org string) bool {
	for _, allowed := range d.autoCreateOrgs {
		if allowed == "*" || allowed == org {
			return true
		}
	}
	return false
}
