package main

import (
	"context"

	"github.com/k8shell-io/identity/pkg/log"
	"github.com/k8shell-io/identity/pkg/server"
)

func main() {
	log.JsonLogger = false
	log := log.NewLogger("main")

	server, err := server.NewServer("config/config.yaml")
	if err != nil {
		log.Error().Msgf("Error starting server: %v\n", err)
		return
	}

	server.RestApi.Serve(context.Background())
}
