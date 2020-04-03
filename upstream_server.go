package main

import (
	"crypto/sha1"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/xtaci/kcp-go"
	"golang.org/x/crypto/pbkdf2"

	"snet/config"
	"snet/utils"
)

func runTLSServer(c *config.Config) {
	if c.UpstreamTLSToken == "" {
		exitOnError(errors.New("missing upstream-tls-token"), nil)
	}
	cert, err := tls.LoadX509KeyPair(c.UpstreamTLSCRT, c.UpstreamTLSKey)
	exitOnError(err, nil)
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}}
	ln, err := tls.Listen("tcp", c.UpstreamTLSServerListen, tlsCfg)
	exitOnError(err, nil)
	l.Info("TLS server running:", c.UpstreamTLSServerListen)
	defer ln.Close()
	for {
		conn, err := ln.Accept()
		if err != nil {
			l.Error(err)
			continue
		}
		go handle(conn, c)
	}
}

func handle(conn net.Conn, c *config.Config) {
	defer conn.Close()
	b := make([]byte, 2)
	if _, err := conn.Read(b); err != nil {
		l.Error(err)
		return
	}
	tlen := binary.BigEndian.Uint16(b)
	b = make([]byte, int(tlen))
	if _, err := conn.Read(b); err != nil {
		l.Error(err)
		return
	}
	if string(b) != c.UpstreamTLSToken {
		l.Error("invalid token", string(b))
		return
	}

	b = make([]byte, 2)
	if _, err := conn.Read(b); err != nil {
		l.Error(err)
		return
	}
	hlen := binary.BigEndian.Uint16(b)
	b = make([]byte, int(hlen))
	if _, err := conn.Read(b); err != nil {
		l.Error(err)
		return
	}
	host := string(b)
	b = make([]byte, 2)
	if _, err := conn.Read(b); err != nil {
		l.Error(err)
		return
	}
	port := int(binary.BigEndian.Uint16(b))
	dstConn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		l.Error(err)
		return
	}
	defer dstConn.Close()
	if err := utils.Pipe(conn, dstConn, time.Duration(30)*time.Second); err != nil {
		l.Error(err)
	}
}

func runKCPServer(c *config.Config) {
	// TODO check

	key := pbkdf2.Key([]byte("test pass"), []byte("test salt"), 1024, 32, sha1.New)
	block, _ := kcp.NewAESBlockCrypt(key)
	if listener, err := kcp.ListenWithOptions("0.0.0.0:9998", block, 10, 3); err == nil {
		for {
			s, err := listener.AcceptKCP()
			if err != nil {
				l.Error(err)
			}
			go handle(s, c)
		}
	} else {
		exitOnError(err, nil)
	}
}
