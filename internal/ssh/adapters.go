package ssh

import "golang.org/x/crypto/ssh"

type clientAdapter struct {
	*Client
}

func (c *clientAdapter) Conn() ssh.Conn {
	return c.Client.Conn
}