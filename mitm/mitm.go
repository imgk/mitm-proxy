package mitm

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"time"

	// add http.pprof
	_ "net/http/pprof"

	"golang.org/x/net/http2"

	"github.com/gorilla/websocket"

	"github.com/imgk/mitm-proxy/adblock"
	"github.com/imgk/mitm-proxy/gencert"
)

var (
	// AddrPort80 is ...
	AddrPort80 = (*net.TCPAddr)(nil)
	// AddrPort443 is ...
	AddrPort443 = (*net.TCPAddr)(nil)
)

func init() {
	var (
		port80  string
		port443 string
	)
	if s := os.Getenv("ADDR_PORT_HTTP"); s == "" {
		port80 = "127.0.0.1:80"
	} else {
		port80 = s
	}
	if s := os.Getenv("ADDR_PORT_HTTPS"); s == "" {
		port443 = "127.0.0.1:443"
	} else {
		port443 = s
	}
	addr, err := ResolveAddr(port80)
	if err != nil {
		log.Panic(err)
	}
	AddrPort80 = addr
	addr, err = ResolveAddr(port443)
	if err != nil {
		log.Panic(err)
	}
	AddrPort443 = addr
}

// ResolveAddr is ...
func ResolveAddr(s string) (*net.TCPAddr, error) {
	return net.ResolveTCPAddr("tcp", s)
}

// Listen is ...
func Listen(addr *net.TCPAddr) (net.Listener, error) {
	return net.ListenTCP("tcp", addr)
}

// Dial is ...
func Dial(addr *net.TCPAddr) (net.Conn, error) {
	return net.DialTCP("tcp", nil, addr)
}

// Run is ...
func Run() {
	var conf struct {
		Cert    string
		Key     string
		Listen  string
		Proxy   string
		Adblock string
	}
	flag.StringVar(&conf.Cert, "cert", "root.crt", "cert file")
	flag.StringVar(&conf.Key, "key", "root.key", "private key file")
	flag.StringVar(&conf.Listen, "l", ":1080", "listen address")
	flag.StringVar(&conf.Proxy, "p", "", "proxy server address: socks5://192.168.1.1:1080")
	flag.StringVar(&conf.Adblock, "r", "", "adblock plus rule file")
	flag.Parse()

	s, err := NewServer(conf.Listen, conf.Cert, conf.Key, conf.Proxy, conf.Adblock)
	if err != nil {
		log.Panic(err)
	}
	if err := s.Serve(); err != nil {
		log.Panic(err)
	}

	log.Println("start mitm proxy server ...")
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	<-sigCh
}

// Server is ...
type Server struct {
	Addr     string
	Dialer   websocket.Dialer
	Upgrader websocket.Upgrader

	// tls.Config to generate fake certificate
	cfg tls.Config

	// proxy server
	srv http.Server
	// http server
	msrv1 http.Server
	// https server
	msrv2 http.Server

	// http1
	t1 *http.Transport
	// http2
	t2 *http2.Transport

	// filter request with rules written in Adblock Plus rule type
	matcher *adblock.RuleMatcher
}

// NewServer is ...
func NewServer(addr, cert, key, proxy, rules string) (*Server, error) {
	// configure proxy
	t1 := &http.Transport{
		Proxy: nil,
	}
	// set proxy for http1
	if proxy != "" {
		u, err := url.Parse(proxy)
		if err != nil {
			return nil, err
		}
		switch u.Scheme {
		case "socks5", "http", "https":
		default:
			return nil, errors.New("proxy scheme error")
		}
		t1.Proxy = http.ProxyURL(u)
	}
	// set proxy for http2
	t2, err := http2.ConfigureTransports(t1)
	if err != nil {
		return nil, err
	}

	// configure certificate
	cache, err := gencert.NewCertificateCache(cert, key)
	if err != nil {
		return nil, err
	}

	// read rules
	matcher := (*adblock.RuleMatcher)(nil)
	if rules != "" {
		matcher, _, err = adblock.NewMatcherFromFiles(rules)
		if err != nil {
			return nil, err
		}
	}

	s := &Server{
		Addr: addr,
		Dialer: websocket.Dialer{
			Proxy: t1.Proxy,
		},
		Upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true },
		},
		cfg: tls.Config{
			GetCertificate: cache.GetCertificate,
		},
		srv:     http.Server{},
		msrv1:   http.Server{},
		msrv2:   http.Server{},
		t1:      t1,
		t2:      t2,
		matcher: matcher,
	}

	s.srv.Handler = http.Handler(s)
	s.msrv1.Handler = http.HandlerFunc(s.ServeMITM)
	s.msrv2.Handler = http.HandlerFunc(s.ServeMITM)
	return s, nil
}

// Serve is ...
func (s *Server) Serve() error {
	l1, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return err
	}
	l2, err := Listen(AddrPort80)
	if err != nil {
		return err
	}
	l3, err := Listen(AddrPort443)
	if err != nil {
		return err
	}

	// proxy
	go s.srv.Serve(l1)
	// serve http
	go s.msrv1.Serve(l2)
	// serve https
	go s.msrv2.Serve(tls.NewListener(l3, &s.cfg))
	return nil
}

// server http proxy: GET and CONNECT
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if err := recover(); err != nil {
			log.Printf("ServeHTTP recover from error: %v\n", err)
		}
		return
	}()

	// http proxy method GET
	if r.Method == http.MethodGet && r.URL.Host != "" {
		s.ServeMITM(w, r)
		return
	}
	// redirect non CONNECT method
	if r.Method != http.MethodConnect {
		http.DefaultServeMux.ServeHTTP(w, r)
		return
	}
	// only allow HTTP/1.1
	if r.ProtoMajor != 1 {
		http.DefaultServeMux.ServeHTTP(w, r)
		return
	}

	// hijack underlying net.Conn
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "", http.StatusInternalServerError)
		log.Println("not a http.Hijacker error")
		return
	}
	conn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, "", http.StatusInternalServerError)
		log.Printf("http.Hijacker hijack error: %v\n", err)
		return
	}
	defer conn.Close()

	// write response
	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		log.Printf("write response back to client error: %v\n", err)
		return
	}

	// determine http or https
	_, port, err := net.SplitHostPort(r.Host)
	if err != nil {
		log.Printf("split host port error: %v\n", err)
		return
	}
	rc := net.Conn(nil)
	switch port {
	case "80":
		// log.Printf("handle http request from %v to %v\n", r.RemoteAddr, r.Host)
		rc, err = Dial(AddrPort80)
	case "443":
		// log.Printf("handle https request from %v to %v\n", r.RemoteAddr, r.Host)
		rc, err = Dial(AddrPort443)
	default:
		// log.Printf("reject https request from %v to %v\n", r.RemoteAddr, r.Host)
		return
	}
	if err != nil {
		log.Printf("dial remote error: %v", err)
		return
	}
	defer rc.Close()

	type CloseWriter interface {
		CloseWrite() error
	}

	// rc -> conn
	errCh := make(chan error, 1)
	go func(conn, rc net.Conn, errCh chan error) {
		_, err := io.Copy(conn, rc)
		if closer, ok := conn.(CloseWriter); ok {
			closer.CloseWrite()
		}
		errCh <- err
	}(conn, rc, errCh)

	// conn -> rc
	_, err = io.Copy(rc, conn)
	if closer, ok := rc.(CloseWriter); ok {
		closer.CloseWrite()
	}

	checkErr := func(direction string, err error) {
		if err == nil {
			return
		}
		log.Printf("relay (%v) CONNECT error: %v\n", direction, err)
	}

	checkErr("c -> rc", err)
	err = <-errCh
	checkErr("rc -> c", err)
	return
}

// copy http.Request
func copyRequest(r *http.Request) (*http.Request, error) {
	rr := *r

	// copy Request.URL
	url := *r.URL
	url.Host = r.Host
	if websocket.IsWebSocketUpgrade(r) {
		if r.TLS == nil {
			url.Scheme = "ws"
		} else {
			url.Scheme = "wss"
		}
	} else {
		if r.TLS == nil {
			url.Scheme = "http"
		} else {
			url.Scheme = "https"
		}
	}
	rr.URL = &url

	// clone Request.Header
	header := r.Header.Clone()
	if header.Get("Host") == "" {
		header.Add("Host", rr.Host)
	}
	rr.Header = header

	// copy request body for HTTP/2
	if rr.ProtoMajor != 2 {
		return &rr, nil
	}

	// get length
	n := r.ContentLength
	// ignore big body
	if n < 1 || n > (32<<10) {
		return &rr, nil
	}

	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, fmt.Errorf("read r.Body all error: %w", err)
	}

	// add http.Request.GetBody
	rr.Body = ioutil.NopCloser(bytes.NewReader(b))
	rr.GetBody = func() (io.ReadCloser, error) {
		return ioutil.NopCloser(bytes.NewReader(b)), nil
	}

	//
	rr.Close = false

	return &rr, nil
}

// ServeMITM is ...
func (s *Server) ServeMITM(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if err := recover(); err != nil {
			log.Printf("ServeMITM recover from error: %v\n", err)
		}
		return
	}()

	// copy http.Request
	rr, err := copyRequest(r)
	if err != nil {
		log.Printf("CopyRequest error: %v\n", err)
		return
	}

	// filter request
	if s.matcher != nil {
		b, _, err := s.matcher.Match(&adblock.Request{
			URL:     rr.URL.String(),
			Domain:  rr.URL.Host,
			Timeout: 200 * time.Millisecond,
		})
		if b {
			log.Printf("BLOCK: %s%s\n", rr.URL.Host, rr.URL.Path)
			http.HandlerFunc(http.NotFound).ServeHTTP(w, r)
			return
		}
		if err != nil {
			log.Printf("match rule error: %v", err)
		}
		log.Printf("ALLOW: %s%s\n", rr.URL.Host, rr.URL.Path)
	}

	// handle websocket
	if rr.URL.Scheme[0] == 'w' {
		s.ServeWebSocket(w, rr, r)
		return
	}

	// select RoundTripper
	rt := http.RoundTripper(nil)
	switch rr.ProtoMajor {
	case 1:
		rt = s.t1
	case 2:
		rt = s.t2
	}

	// get response
	resp, err := rt.RoundTrip(rr)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, io.EOF) {
			return
		}
		log.Printf("RoundTrip error: %v\n", err)
		return
	}
	defer resp.Body.Close()

	// copy header
	func(w, r http.Header) {
		for k, v := range r {
			for _, vv := range v {
				w.Add(k, vv)
			}
		}
	}(w.Header(), resp.Header)

	// write response code
	w.WriteHeader(resp.StatusCode)

	// return when there is no body
	if rr.Method == http.MethodHead {
		return
	}
	switch resp.StatusCode {
	case http.StatusContinue, http.StatusSwitchingProtocols, http.StatusProcessing:
		return
	case http.StatusEarlyHints, http.StatusNoContent, http.StatusNotModified:
		return
	default:
	}

	// write response body
	if _, err := io.Copy(w, resp.Body); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
			return
		}
		log.Printf("io.Copy error: %v\n", err)
	}
}

// ServeWebSocket is ...
func (s *Server) ServeWebSocket(w http.ResponseWriter, rr, r *http.Request) {
	// remove duplicated header
	for _, k := range []string{
		"Sec-Websocket-Extensions",
		"Sec-Websocket-Version",
		"Sec-Websocket-Key",
		"Connection",
		"Upgrade",
	} {
		rr.Header.Del(k)
	}

	// dial remote
	rc, _, err := s.Dialer.Dial(rr.URL.String(), rr.Header)
	if err != nil {
		http.HandlerFunc(http.NotFound).ServeHTTP(w, rr)
		log.Printf("dial websocket error: %v\n", err)
		return
	}
	defer rc.Close()

	// upgrade local
	header := make(http.Header)
	c, err := s.Upgrader.Upgrade(w, r, header)
	if err != nil {
		log.Printf("upgrade websocket error: %v\n", err)
		return
	}
	defer c.Close()

	// c -> rc
	errCh := make(chan error, 1)
	go func(c, rc *websocket.Conn, errCh chan error) {
		for {
			n, b, err := c.ReadMessage()
			if err != nil {
				errCh <- err
				break
			}
			if err := rc.WriteMessage(n, b); err != nil {
				errCh <- err
				break
			}
		}
		rc.WriteControl(websocket.CloseMessage, nil, time.Now().Add(5*time.Second))
	}(c, rc, errCh)

	// rc -> c
	for {
		n, b, e := rc.ReadMessage()
		if e != nil {
			err = e
			break
		}
		if err = c.WriteMessage(n, b); err != nil {
			break
		}
	}
	c.WriteControl(websocket.CloseMessage, nil, time.Now().Add(5*time.Second))

	checkErr := func(direction string, err error) {
		if err == nil {
			return
		}
		if ce := (*websocket.CloseError)(nil); errors.As(err, &ce) {
			switch ce.Code {
			case websocket.CloseNormalClosure:
				return
			case websocket.CloseGoingAway:
				return
			case websocket.CloseNoStatusReceived:
				return
			default:
			}
		}
		if errors.Is(err, websocket.ErrCloseSent) {
			return
		}
		log.Printf("websocket (%v) error: %v\n", direction, err)
	}

	checkErr("rc -> c", err)
	err = <-errCh
	checkErr("c -> rc", err)
	return
}
