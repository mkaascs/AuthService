package config

import (
	"errors"
	"flag"
	"fmt"
	"github.com/ilyakaznacheev/cleanenv"
	"github.com/joho/godotenv"
	"log"
	"os"
	"time"
)

type Config struct {
	Env                string `yaml:"environment" env-default:"local"`
	DbHost             string `yaml:"db_host" env-required:"true"`
	DbPassword         string `yaml:"-" env-required:"true" env:"MYSQL_ROOT_PASSWORD"`
	DbConnectionString string `yaml:"-"`
	GrpcConfig         `yaml:"grpc"`
	AuthConfig         `yaml:"auth"`
}

type GrpcConfig struct {
	Port    int           `yaml:"port" env-required:"true"`
	Timeout time.Duration `yaml:"timeout" env-default:"5s"`
}

type AuthConfig struct {
	Issuer          string        `yaml:"issuer" env-default:"auth-service"`
	AccessTokenTTL  time.Duration `yaml:"access_token_ttl" env-default:"15m"`
	RefreshTokenTTL time.Duration `yaml:"refresh_token_ttl" env-default:"720h"`
}

func MustLoad() *Config {
	config, err := Load()
	if err != nil {
		log.Fatal(err)
	}

	return config
}

func Load() (*Config, error) {
	path := fetchConfigPath()

	if path == "" {
		return nil, errors.New("config file not specified")
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, errors.New("config file does not exist: " + path)
	}

	var config Config
	if err := cleanenv.ReadConfig(path, &config); err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	config.DbConnectionString = fmt.Sprintf(
		"root:%s@tcp(%s)/URLShortener?charset=utf8&parseTime=True",
		config.DbPassword,
		config.DbHost)

	return &config, nil
}

func fetchConfigPath() string {
	var path string

	flag.StringVar(&path, "config", "", "path to config file")
	flag.Parse()

	if path == "" {
		if err := godotenv.Load(".env"); err != nil {
			return ""
		}

		path = os.Getenv("CONFIG_PATH")
	}

	return path
}
