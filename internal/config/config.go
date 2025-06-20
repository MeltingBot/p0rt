package config

import (
	"fmt"
	"gopkg.in/yaml.v3"
	"os"
)

type Config struct {
	Server  ServerConfig  `yaml:"server"`
	Domain  DomainConfig  `yaml:"domain"`
	Storage StorageConfig `yaml:"storage"`
}

type ServerConfig struct {
	SSH  SSHServerConfig  `yaml:"ssh"`
	HTTP HTTPServerConfig `yaml:"http"`
}

type SSHServerConfig struct {
	Port    int    `yaml:"port"`
	HostKey string `yaml:"host_key"`
}

type HTTPServerConfig struct {
	Port int `yaml:"port"`
}

type DomainConfig struct {
	Base                string `yaml:"base"`
	ReservationsEnabled bool   `yaml:"reservations_enabled"`
}

type StorageConfig struct {
	Type          string `yaml:"type"`      // "json" or "redis"
	DataDir       string `yaml:"data_dir"`  // For JSON store
	RedisURL      string `yaml:"redis_url"` // For Redis store
	RedisPassword string `yaml:"redis_password"`
	RedisDB       int    `yaml:"redis_db"`
}

// Load loads configuration from YAML file and environment variables
func Load() (*Config, error) {
	config := &Config{}

	// Load from YAML file if it exists
	configPath := getEnv("CONFIG_FILE", "config.yaml")
	if _, err := os.Stat(configPath); err == nil {
		data, err := os.ReadFile(configPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}

		if err := yaml.Unmarshal(data, config); err != nil {
			return nil, fmt.Errorf("failed to parse config file: %w", err)
		}
	} else {
		// Set defaults if no config file
		config = GetDefaultConfig()
	}

	// Override with environment variables
	overrideWithEnv(config)

	return config, nil
}

// LoadDefault loads default configuration without YAML file
func LoadDefault() *Config {
	config := GetDefaultConfig()
	overrideWithEnv(config)
	return config
}

func GetDefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			SSH: SSHServerConfig{
				Port:    2222,
				HostKey: "",
			},
			HTTP: HTTPServerConfig{
				Port: 80,
			},
		},
		Domain: DomainConfig{
			Base: "p0rt.xyz",
		},
		Storage: StorageConfig{
			Type:    "json",
			DataDir: "./data",
		},
	}
}

func overrideWithEnv(config *Config) {
	if port := getEnv("SSH_SERVER_PORT", ""); port != "" {
		if p := parseInt(port, config.Server.SSH.Port); p > 0 {
			config.Server.SSH.Port = p
		}
	}
	if port := getEnv("HTTP_PORT", ""); port != "" {
		if p := parseInt(port, config.Server.HTTP.Port); p > 0 {
			config.Server.HTTP.Port = p
		}
	}
	if key := getEnv("SSH_HOST_KEY", ""); key != "" {
		config.Server.SSH.HostKey = key
	}
	if domain := getEnv("DOMAIN_BASE", ""); domain != "" {
		config.Domain.Base = domain
	}
	if reservations := getEnv("DOMAIN_RESERVATIONS_ENABLED", ""); reservations != "" {
		config.Domain.ReservationsEnabled = reservations == "true" || reservations == "1"
	}

	// Storage configuration
	if storageType := getEnv("STORAGE_TYPE", ""); storageType != "" {
		config.Storage.Type = storageType
	}
	if dataDir := getEnv("STORAGE_DATA_DIR", ""); dataDir != "" {
		config.Storage.DataDir = dataDir
	}
	if redisURL := getEnv("REDIS_URL", ""); redisURL != "" {
		config.Storage.RedisURL = redisURL
	}
	if redisPassword := getEnv("REDIS_PASSWORD", ""); redisPassword != "" {
		config.Storage.RedisPassword = redisPassword
	}
	if redisDB := getEnv("REDIS_DB", ""); redisDB != "" {
		if db := parseInt(redisDB, 0); db >= 0 {
			config.Storage.RedisDB = db
		}
	}
}

// Helper methods for backward compatibility
func (c *Config) GetSSHPort() string {
	return fmt.Sprintf("%d", c.Server.SSH.Port)
}

func (c *Config) GetHTTPPort() string {
	return fmt.Sprintf("%d", c.Server.HTTP.Port)
}

func (c *Config) GetSSHHostKey() string {
	return c.Server.SSH.HostKey
}

func (c *Config) GetDomainBase() string {
	return c.Domain.Base
}

func (c *Config) GetStorageConfig() StorageConfig {
	return c.Storage
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func parseInt(s string, defaultValue int) int {
	var i int
	if n, _ := fmt.Sscanf(s, "%d", &i); n == 1 {
		return i
	}
	return defaultValue
}
