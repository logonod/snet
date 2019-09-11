package ssr

import (
	"fmt"
	"net"
	"net/url"
	"time"

	ss "github.com/sun8911879/shadowsocksR"
	"github.com/sun8911879/shadowsocksR/tools/leakybuf"
	"github.com/sun8911879/shadowsocksR/tools/socks"

	"snet/proxy"
)

type Config struct {
	Host          string
	Port          int
	CipherMethod  string
	Password      string
	Protocol      string
	ProtocolParam string
	Obfs          string
	ObfsParam     string
	Timeout       time.Duration
}

type SSInfo struct {
	SSRInfo
	EncryptMethod   string
	EncryptPassword string
}

type SSRInfo struct {
	Obfs          string
	ObfsParam     string
	ObfsData      interface{}
	Protocol      string
	ProtocolParam string
	ProtocolData  interface{}
}

type BackendInfo struct {
	SSInfo
	Address string
	Type    string
}

type Server struct {
	Host net.IP
	Port int
	bi   *BackendInfo
	cfg  *Config
}

func (s *Server) Init(c proxy.Config) error {
	s.cfg = c.(*Config)
	ips, err := net.LookupIP(s.cfg.Host)
	if err != nil {
		return err
	}
	s.Host = ips[0]
	s.Port = s.cfg.Port
	s.bi = &BackendInfo{
		Address: fmt.Sprintf("%s:%d", s.Host, s.Port),
		Type:    "ssr",
		SSInfo: SSInfo{
			EncryptMethod:   s.cfg.CipherMethod,
			EncryptPassword: s.cfg.Password,
			SSRInfo: SSRInfo{
				Protocol:      s.cfg.Protocol,
				ProtocolParam: s.cfg.ProtocolParam,
				Obfs:          s.cfg.Obfs,
				ObfsParam:     s.cfg.ObfsParam,
			},
		},
	}
	if err != nil {
		return err
	}
	return nil
}

func (s *Server) GetProxyIP() net.IP {
	return s.Host
}

func (s *Server) Dial(dstHost string, dstPort int) (net.Conn, error) {
	u := &url.URL{
		Scheme: s.bi.Type,
		Host:   s.bi.Address,
	}
	v := u.Query()
	v.Set("encrypt-method", s.bi.EncryptMethod)
	v.Set("encrypt-key", s.bi.EncryptPassword)
	v.Set("obfs", s.bi.Obfs)
	v.Set("obfs-param", s.bi.ObfsParam)
	v.Set("protocol", s.bi.Protocol)
	v.Set("protocol-param", s.bi.ProtocolParam)
	u.RawQuery = v.Encode()
	ssrconn, err := ss.NewSSRClient(u)
	if err != nil {
		return nil, fmt.Errorf("connecting to SSR server failed :%v", err)
	}

	if s.bi.ObfsData == nil {
		s.bi.ObfsData = ssrconn.IObfs.GetData()
	}
	ssrconn.IObfs.SetData(s.bi.ObfsData)

	if s.bi.ProtocolData == nil {
		s.bi.ProtocolData = ssrconn.IProtocol.GetData()
	}
	ssrconn.IProtocol.SetData(s.bi.ProtocolData)

	if _, err := ssrconn.Write(socks.ParseAddr(fmt.Sprintf("%s:%d", dstHost, dstPort))); err != nil {
		ssrconn.Close()
		return nil, err
	}
	return ssrconn, nil
}

func (s *Server) Pipe(src, dst net.Conn) error {
	defer dst.Close()
	buf := leakybuf.GlobalLeakyBuf.Get()
	defer leakybuf.GlobalLeakyBuf.Put(buf)
	for {
		src.SetReadDeadline(time.Now().Add(s.cfg.Timeout))
		n, err := src.Read(buf)
		// read may return EOF with n > 0
		// should always process n > 0 bytes before handling error
		if n > 0 {
			// Note: avoid overwrite err returned by Read.
			if _, err := dst.Write(buf[0:n]); err != nil {
				fmt.Println("xxxx", err)
				break
			}
		}
		if err != nil {
			// Always "use of closed network connection", but no easy way to
			// identify this specific error. So just leave the error along for now.
			// More info here: https://code.google.com/p/go/issues/detail?id=4373
			break
		}
	}
	return nil
}

func (s *Server) Close() error {
	return nil
}

func init() {
	proxy.Register("ssr", new(Server))
}
