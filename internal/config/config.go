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
	RedisConfig        `yaml:"redis"`
	RateLimiterConfig  `yaml:"rate_limiter"`
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

type RedisConfig struct {
	Host        string        `yaml:"host" env-required:"true"`
	Password    string        `yaml:"-" env-required:"true" env:"REDIS_PASSWORD"`
	DB          int           `yaml:"db" env-default:"0"`
	MaxRetries  int           `yaml:"max_retries" env-default:"5"`
	DialTimeout time.Duration `yaml:"dial_timeout" env-default:"10s"`
	Timeout     time.Duration `yaml:"timeout" env-default:"5s"`
}

type RateLimiterConfig struct {
	MaxAttempts   int           `yaml:"max_attempts" env-default:"5"`
	Window        time.Duration `yaml:"window" env-default:"10m"`
	BlockDuration time.Duration `yaml:"block_duration" env-default:"5m"`
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
		"root:%s@tcp(%s)/AuthService?charset=utf8&parseTime=True",
		config.DbPassword,
		config.DbHost)

	return &config, nil
}

func fetchConfigPath() string {
	var path string

	flag.StringVar(&path, "config", "", "path to config file")
	flag.Parse()

	if path == "" {
		_ = godotenv.Load()
		path = os.Getenv("CONFIG_PATH")
	}

	return path
}
