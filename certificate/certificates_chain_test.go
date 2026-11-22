package certificate

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"sync/atomic"
	"time"

	"github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/certcrypto"
)

type testCert struct {
	cert *x509.Certificate
	der  []byte
	key  *ecdsa.PrivateKey
}

type testChain struct {
	leaf         *testCert
	intermediate *testCert
	root         *testCert
}

var testCertSerial atomic.Int64

func nextTestSerial() *big.Int {
	return big.NewInt(testCertSerial.Add(1))
}

func newTestCA(commonName string) (*testCert, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber:          nextTestSerial(),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}

	return &testCert{cert: cert, der: der, key: key}, nil
}

func issueTestCert(commonName string, isCA bool, parent *testCert) (*testCert, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: nextTestSerial(),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	if isCA {
		template.IsCA = true
		template.BasicConstraintsValid = true
		template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature
	}

	der, err := x509.CreateCertificate(rand.Reader, template, parent.cert, &key.PublicKey, parent.key)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}

	return &testCert{cert: cert, der: der, key: key}, nil
}

func newTestChain(rootCN, intermediateCN, leafCN string) (*testChain, error) {
	root, err := newTestCA(rootCN)
	if err != nil {
		return nil, err
	}

	intermediate, err := issueTestCert(intermediateCN, true, root)
	if err != nil {
		return nil, err
	}

	leaf, err := issueTestCert(leafCN, false, intermediate)
	if err != nil {
		return nil, err
	}

	return &testChain{leaf: leaf, intermediate: intermediate, root: root}, nil
}

// withRoot re-signs the receiver chain's intermediate under a new root. The
// leaf and intermediate are shared with the original chain, so an alternate
// response built from both chains serves the exact same leaf certificate and
// only diverges at the trust anchor, like real ACME alternate chains.
func (c *testChain) withRoot(rootCN string) (*testChain, error) {
	root, err := newTestCA(rootCN)
	if err != nil {
		return nil, err
	}

	template := c.intermediate.cert
	template.Raw = nil
	template.RawTBSCertificate = nil
	template.RawSubject = nil
	template.RawIssuer = nil

	der, err := x509.CreateCertificate(rand.Reader, template, root.cert, c.intermediate.cert.PublicKey, root.key)
	if err != nil {
		return nil, err
	}

	intermediate, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}

	return &testChain{
		leaf: c.leaf,
		intermediate: &testCert{
			cert: intermediate,
			der:  der,
			key:  c.intermediate.key,
		},
		root: root,
	}, nil
}

// rawBundled builds a bundled CA response, where the certificate part holds
// the whole chain and the issuer part holds everything but the leaf.
func (c *testChain) rawBundled() *acme.RawCertificate {
	cert := pemChain(c.leaf, c.intermediate, c.root)

	return &acme.RawCertificate{
		Cert:   cert,
		Issuer: pemChain(c.intermediate, c.root),
	}
}

// rawSplit builds a non-bundled CA response, where the certificate part only
// holds the leaf and the issuer part holds the rest of the chain.
func (c *testChain) rawSplit() *acme.RawCertificate {
	return &acme.RawCertificate{
		Cert:   pemChain(c.leaf),
		Issuer: pemChain(c.intermediate, c.root),
	}
}

func pemChain(certs ...*testCert) []byte {
	var data []byte

	for _, cert := range certs {
		data = append(data, certcrypto.PEMEncode(certcrypto.DERCertificateBytes(cert.der))...)
	}

	return data
}
