package config

import (
	"fmt"
	"os"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Server ServerConfig `yaml:"server"`
	Domain DomainConfig `yaml:"domain"`
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
	Base string `yaml:"base"`
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
		config = getDefaultConfig()
	}
	
	// Override with environment variables
	overrideWithEnv(config)
	
	return config, nil
}

// LoadDefault loads default configuration without YAML file
func LoadDefault() *Config {
	config := getDefaultConfig()
	overrideWithEnv(config)
	return config
}

func getDefaultConfig() *Config {
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