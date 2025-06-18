package tcp

import (
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

type Manager struct {
	forwarders map[int]*Forwarder
	mu         sync.RWMutex
}

type Forwarder struct {
	listener net.Listener
	port     int
	client   SSHClient
}

type SSHClient interface {
	Conn() ssh.Conn
}

func NewManager() *Manager {
	return &Manager{
		forwarders: make(map[int]*Forwarder),
	}
}

func (m *Manager) CreateForwarder(client SSHClient, bindAddr string, bindPort uint32) (int, error) {
	port := m.findAvailablePort()

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return 0, fmt.Errorf("failed to listen on port %d: %w", port, err)
	}

	forwarder := &Forwarder{
		listener: listener,
		port:     port,
		client:   client,
	}

	m.mu.Lock()
	m.forwarders[port] = forwarder
	m.mu.Unlock()

	go m.handleForwarder(forwarder, bindAddr, bindPort)

	log.Printf("Created TCP forwarder on port %d", port)
	return port, nil
}

func (m *Manager) Close(port int) error {
	m.mu.Lock()
	forwarder, exists := m.forwarders[port]
	if exists {
		delete(m.forwarders, port)
	}
	m.mu.Unlock()

	if !exists {
		return fmt.Errorf("forwarder not found for port %d", port)
	}

	err := forwarder.listener.Close()
	log.Printf("Closed TCP forwarder on port %d", port)
	return err
}

func (m *Manager) findAvailablePort() int {
	rand.Seed(time.Now().UnixNano())

	for attempts := 0; attempts < 100; attempts++ {
		port := 50000 + rand.Intn(2000)

		m.mu.RLock()
		_, exists := m.forwarders[port]
		m.mu.RUnlock()

		if !exists {
			listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
			if err == nil {
				listener.Close()
				return port
			}
		}
	}

	return 50000 + rand.Intn(2000)
}

func (m *Manager) handleForwarder(forwarder *Forwarder, bindAddr string, bindPort uint32) {
	for {
		conn, err := forwarder.listener.Accept()
		if err != nil {
			return
		}

		go m.handleConnection(conn, forwarder.client, bindAddr, bindPort)
	}
}

func (m *Manager) handleConnection(localConn net.Conn, client SSHClient, bindAddr string, bindPort uint32) {
	defer localConn.Close()

	remoteAddr := localConn.RemoteAddr().String()

	channel, reqs, err := client.Conn().OpenChannel("forwarded-tcpip", ssh.Marshal(&forwardedTCPIPData{
		DestAddr:   bindAddr,
		DestPort:   bindPort,
		OriginAddr: remoteAddr,
		OriginPort: 0,
	}))

	if err != nil {
		log.Printf("Failed to open forwarded channel: %v", err)
		return
	}
	defer channel.Close()

	go ssh.DiscardRequests(reqs)

	errChan := make(chan error, 2)

	go func() {
		_, err := io.Copy(channel, localConn)
		errChan <- err
	}()

	go func() {
		_, err := io.Copy(localConn, channel)
		errChan <- err
	}()

	<-errChan
}

type forwardedTCPIPData struct {
	DestAddr   string
	DestPort   uint32
	OriginAddr string
	OriginPort uint32
}

func (m *Manager) GetActiveForwarders() map[int]string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	active := make(map[int]string)
	for port, forwarder := range m.forwarders {
		active[port] = forwarder.listener.Addr().String()
	}
	return active
}
