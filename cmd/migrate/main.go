package main

import (
	"auth-service/internal/config"
	"errors"
	"fmt"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/mysql"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"log"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("usage: migrate <up/down>")
	}

	direction := os.Args[1]
	if direction != "up" && direction != "down" {
		log.Fatal("usage: migrate <up/down>")
	}

	cfg := config.MustLoad()

	mgr, err := migrate.New("file://migrations", "mysql://"+cfg.DbConnectionString)
	if err != nil {
		log.Fatalf("failed to init migrator: %v", err)
	}

	defer func() {
		if err, _ := mgr.Close(); err != nil {
			log.Fatalf("failed to close migrator: %v", err)
		}
	}()

	operations := map[string]func() error{
		"up":   mgr.Up,
		"down": mgr.Down,
	}

	if err := operations[direction](); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		log.Fatalf("failed to run migrations: %v", err)
	}

	fmt.Println("migration complete")
}
