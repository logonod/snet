package kcp

import (
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"net"

	"github.com/xtaci/kcp-go"
	"golang.org/x/crypto/pbkdf2"

	"snet/proxy"
)

type Config struct {
	Host  net.IP
	Port  int
	Token string
}

type Server struct {
	Host  net.IP
	Port  int
	block kcp.BlockCrypt
	cfg   *Config
}

func (s *Server) Init(c proxy.Config) error {
	s.cfg = c.(*Config)
	s.Host = s.cfg.Host
	s.Port = s.cfg.Port
	// TODO add check
	key := pbkdf2.Key([]byte("test pass"), []byte("test salt"), 1024, 32, sha1.New)
	block, err := kcp.NewAESBlockCrypt(key)
	if err != nil {
		return err
	}
	s.block = block
	return nil
}

func (s *Server) Dial(dstHost string, dstPort int) (net.Conn, error) {
	conn, err := kcp.DialWithOptions(fmt.Sprintf("%s:%d", s.Host, s.Port), s.block, 10, 3)
	if err != nil {
		return nil, err
	}
	err = writeDst(conn, s.cfg.Token, dstHost, dstPort)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func writeDst(conn net.Conn, token string, host string, port int) error {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, uint16(len(token)))
	if _, err := conn.Write(buf); err != nil {
		return err
	}
	if _, err := conn.Write([]byte(token)); err != nil {
		return err
	}
	binary.BigEndian.PutUint16(buf, uint16(len(host)))
	if _, err := conn.Write(buf); err != nil {
		return err
	}
	if _, err := conn.Write([]byte(host)); err != nil {
		return err
	}
	binary.BigEndian.PutUint16(buf, uint16(port))
	if _, err := conn.Write(buf); err != nil {
		return err
	}
	return nil
}

func (s *Server) GetProxyIP() net.IP {
	return s.Host
}

func (s *Server) Close() error {
	return nil
}

func init() {
	proxy.Register("kcp", new(Server))
}
