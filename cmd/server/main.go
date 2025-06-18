package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/p0rt/p0rt/internal/config"
	"github.com/p0rt/p0rt/internal/domain"
	"github.com/p0rt/p0rt/internal/proxy"
	"github.com/p0rt/p0rt/internal/ssh"
	"github.com/p0rt/p0rt/internal/tcp"

	cryptossh "golang.org/x/crypto/ssh"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	cfg, err := config.Load()
	if err != nil {
		log.Printf("Failed to load config file, using defaults: %v", err)
		cfg = config.LoadDefault()
	}

	log.Println("Starting P0rt...")
	log.Printf("SSH Port: %s", cfg.GetSSHPort())
	log.Printf("HTTP Port: %s", cfg.GetHTTPPort())
	log.Printf("Domain Base: %s", cfg.GetDomainBase())

	// Create domain generator with storage configuration
	storageConfig := cfg.GetStorageConfig()
	log.Printf("Storage Type: %s", storageConfig.Type)
	if storageConfig.Type == "redis" {
		log.Printf("Redis URL: %s", storageConfig.RedisURL)
	} else {
		log.Printf("Data Dir: %s", storageConfig.DataDir)
	}

	domainGen, err := domain.NewGeneratorFromConfig(
		storageConfig.Type,
		storageConfig.DataDir,
		storageConfig.RedisURL,
		storageConfig.RedisPassword,
		storageConfig.RedisDB,
	)
	if err != nil {
		log.Fatalf("Failed to create domain generator: %v", err)
	}
	tcpManager := tcp.NewManager()

	tcpManagerAdapter := &tcpManagerAdapter{manager: tcpManager}

	sshServer, err := ssh.NewServer(cfg.GetSSHPort(), cfg.GetSSHHostKey(), domainGen, tcpManagerAdapter, cfg.GetDomainBase())
	if err != nil {
		log.Fatalf("Failed to create SSH server: %v", err)
	}

	sshServerAdapter := &sshServerAdapter{server: sshServer, domainGen: domainGen}
	httpProxy := proxy.NewHTTPProxy(sshServerAdapter)

	errChan := make(chan error, 2)

	go func() {
		if err := sshServer.Start(); err != nil {
			errChan <- err
		}
	}()

	go func() {
		if err := httpProxy.Start(cfg.GetHTTPPort()); err != nil {
			errChan <- err
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-errChan:
		log.Fatalf("Server error: %v", err)
	case sig := <-sigChan:
		log.Printf("Received signal %v, shutting down...", sig)
		os.Exit(0)
	}
}

type tcpManagerAdapter struct {
	manager *tcp.Manager
}

func (t *tcpManagerAdapter) CreateForwarder(client *ssh.Client, bindAddr string, bindPort uint32) (int, error) {
	clientAdapter := &clientAdapterForTCP{client: client}
	return t.manager.CreateForwarder(clientAdapter, bindAddr, bindPort)
}

func (t *tcpManagerAdapter) Close(port int) error {
	return t.manager.Close(port)
}

type clientAdapterForTCP struct {
	client *ssh.Client
}

func (c *clientAdapterForTCP) Conn() cryptossh.Conn {
	return c.client.Conn
}

type sshServerAdapter struct {
	server    *ssh.Server
	domainGen *domain.Generator
}

func (s *sshServerAdapter) GetClient(domain string) proxy.ClientWithPort {
	client := s.server.GetClient(domain)
	if client == nil {
		return nil
	}
	return newClientPortAdapter(client)
}

func (s *sshServerAdapter) LogConnection(domain, clientIP, requestURL string) {
	s.server.LogConnection(domain, clientIP, requestURL)
}

func (s *sshServerAdapter) GetDomainStats() map[string]interface{} {
	return s.domainGen.GetStats()
}

type clientPortAdapter struct {
	client *ssh.Client
}

func newClientPortAdapter(client *ssh.Client) *clientPortAdapter {
	return &clientPortAdapter{
		client: client,
	}
}

func (c *clientPortAdapter) GetPort() int {
	return c.client.Port
}
