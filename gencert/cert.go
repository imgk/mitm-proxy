package gencert

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/idna"
)

// CertificateCache is ...
type CertificateCache struct {
	sync.RWMutex
	rootCert string
	rootKey  string
	cert     tls.Certificate
	cache    map[string]*tls.Certificate
}

// NewCertificateCache is ...
func NewCertificateCache(cert, key string) (c *CertificateCache, err error) {
	c = &CertificateCache{
		rootCert: cert,
		rootKey:  key,
	}
	c.cert, err = tls.LoadX509KeyPair(c.rootCert, c.rootKey)
	if err != nil {
		return
	}

	c.cert.Leaf, err = x509.ParseCertificate(c.cert.Certificate[0])
	if err != nil {
		return
	}

	c.cache = make(map[string]*tls.Certificate)
	return
}

// GetCertificate is ...
func (c *CertificateCache) GetCertificate(clientHello *tls.ClientHelloInfo) (cert *tls.Certificate, err error) {
	commonName, err := idna.ToASCII(clientHello.ServerName)
	if err != nil {
		return nil, err
	}
	commonName = strings.ToLower(commonName)

	c.RLock()
	cert, ok := c.cache[commonName]
	c.RUnlock()
	if ok {
		return cert, nil
	}

	cert, err = c.CreateCert(commonName)
	return
}

// CreateCert is ...
func (c *CertificateCache) CreateCert(commonName string) (cert *tls.Certificate, err error) {
	// log.Printf("generate cert for %v\n", commonName)

	c.Lock()
	defer c.Unlock()

	cert, ok := c.cache[commonName]
	if ok {
		return
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization:       []string{"Fake Certificates"},
			OrganizationalUnit: []string{"Fake Certificates"},
			CommonName:         commonName,
		},
		NotBefore:             time.Now().AddDate(0, 0, -7),
		NotAfter:              time.Now().AddDate(1, 11, 23),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	if ip := net.ParseIP(commonName); ip != nil {
		template.IPAddresses = append(template.IPAddresses, ip)
	} else {
		template.DNSNames = append(template.DNSNames, commonName)
	}

	rootCA := &c.cert
	template.AuthorityKeyId = rootCA.Leaf.SubjectKeyId

	var priv *rsa.PrivateKey
	if priv, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
		return
	}
	template.SubjectKeyId = func(n *big.Int) []byte {
		h := sha1.New()
		h.Write(n.Bytes())
		return h.Sum(nil)
	}(priv.N)

	var derBytes []byte
	if derBytes, err = x509.CreateCertificate(rand.Reader, &template, rootCA.Leaf, &priv.PublicKey, rootCA.PrivateKey); err != nil {
		return
	}

	certOut := bytes.NewBuffer(nil)
	if err = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return
	}

	keyOut := bytes.NewBuffer(nil)
	if err = pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}); err != nil {
		return
	}

	tlsCert, err := tls.X509KeyPair(certOut.Bytes(), keyOut.Bytes())
	if err != nil {
		return nil, err
	}

	cert = &tlsCert
	c.cache[commonName] = cert
	return
}
