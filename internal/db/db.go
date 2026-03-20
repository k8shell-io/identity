// Copyright 2025 the k8Shell authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package db provides database access and management for the k8Shell Identity service.
// It provides persistence for users and methods for managing them.
package db

import (
	"fmt"

	"github.com/k8shell-io/common/pkg/db"
)

// DB wraps the shared database implementation for the identity service.
type DB struct {
	db.DB
}

// NewDB creates a new DB for the identity service.
func NewDB(config db.DBConfig) (*DB, error) {
	d, err := db.NewDB(config, "identity")
	if err != nil {
		return nil, fmt.Errorf("create db: %w", err)
	}
	return &DB{DB: *d}, nil
}
