package backend

import (
	"fmt"

	"github.com/k8shell-io/common/pkg/db"
)

type DB struct {
	db.DB
}

func NewDB(config db.DBConfig) (*DB, error) {
	d, err := db.NewDB(config, "identity")
	if err != nil {
		return nil, fmt.Errorf("create db: %w", err)
	}
	return &DB{DB: *d}, nil
}
