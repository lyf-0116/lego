package certificate

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net/http"
	"testing"

	"github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/acme/api"
	"github.com/go-acme/lego/v5/internal/tester"
	"github.com/go-acme/lego/v5/internal/tester/servermock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const certResponseNoBundleMock = `-----BEGIN CERTIFICATE-----
MIIDEDCCAfigAwIBAgIHPhckqW5fPDANBgkqhkiG9w0BAQsFADAoMSYwJAYDVQQD
Ex1QZWJibGUgSW50ZXJtZWRpYXRlIENBIDM5NWU2MTAeFw0xODExMDcxNzQ2NTZa
Fw0yMzExMDcxNzQ2NTZaMBMxETAPBgNVBAMTCGFjbWUud3RmMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwtLNKvZXD20XPUQCWYSK9rUSKxD9Eb0c9fag
bxOxOkLRTgL8LH6yln+bxc3MrHDou4PpDUdeo2CyOQu3CKsTS5mrH3NXYHu0H7p5
y3riOJTHnfkGKLT9LciGz7GkXd62nvNP57bOf5Sk4P2M+Qbxd0hPTSfu52740LSy
144cnxe2P1aDYehrEp6nYCESuyD/CtUHTo0qwJmzIy163Sp3rSs15BuCPyhySnE3
BJ8Ggv+qC6D5I1932DfSqyQJ79iq/HRm0Fn84am3KwvRlUfWxabmsUGARXoqCgnE
zcbJVOZKewv0zlQJpfac+b+Imj6Lvt1TGjIz2mVyefYgLx8gwwIDAQABo1QwUjAO
BgNVHQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMAwG
A1UdEwEB/wQCMAAwEwYDVR0RBAwwCoIIYWNtZS53dGYwDQYJKoZIhvcNAQELBQAD
ggEBABB/0iYhmfPSQot5RaeeovQnsqYjI5ryQK2cwzW6qcTJfv8N6+p6XkqF1+W4
jXZjrQP8MvgO9KNWlvx12vhINE6wubk88L+2piAi5uS2QejmZbXpyYB9s+oPqlk9
IDvfdlVYOqvYAhSx7ggGi+j73mjZVtjAavP6dKuu475ZCeq+NIC15RpbbikWKtYE
HBJ7BW8XQKx67iHGx8ygHTDLbREL80Bck3oUm7wIYGMoNijD6RBl25p4gYl9dzOd
TqGl5hW/1P5hMbgEzHbr4O3BfWqU2g7tV36TASy3jbC3ONFRNNYrpEZ1AL3+cUri
OPPkKtAKAbQkKbUIfsHpBZjKZMU=
-----END CERTIFICATE-----
`

const certResponseMock = `-----BEGIN CERTIFICATE-----
MIIDEDCCAfigAwIBAgIHPhckqW5fPDANBgkqhkiG9w0BAQsFADAoMSYwJAYDVQQD
Ex1QZWJibGUgSW50ZXJtZWRpYXRlIENBIDM5NWU2MTAeFw0xODExMDcxNzQ2NTZa
Fw0yMzExMDcxNzQ2NTZaMBMxETAPBgNVBAMTCGFjbWUud3RmMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwtLNKvZXD20XPUQCWYSK9rUSKxD9Eb0c9fag
bxOxOkLRTgL8LH6yln+bxc3MrHDou4PpDUdeo2CyOQu3CKsTS5mrH3NXYHu0H7p5
y3riOJTHnfkGKLT9LciGz7GkXd62nvNP57bOf5Sk4P2M+Qbxd0hPTSfu52740LSy
144cnxe2P1aDYehrEp6nYCESuyD/CtUHTo0qwJmzIy163Sp3rSs15BuCPyhySnE3
BJ8Ggv+qC6D5I1932DfSqyQJ79iq/HRm0Fn84am3KwvRlUfWxabmsUGARXoqCgnE
zcbJVOZKewv0zlQJpfac+b+Imj6Lvt1TGjIz2mVyefYgLx8gwwIDAQABo1QwUjAO
BgNVHQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMAwG
A1UdEwEB/wQCMAAwEwYDVR0RBAwwCoIIYWNtZS53dGYwDQYJKoZIhvcNAQELBQAD
ggEBABB/0iYhmfPSQot5RaeeovQnsqYjI5ryQK2cwzW6qcTJfv8N6+p6XkqF1+W4
jXZjrQP8MvgO9KNWlvx12vhINE6wubk88L+2piAi5uS2QejmZbXpyYB9s+oPqlk9
IDvfdlVYOqvYAhSx7ggGi+j73mjZVtjAavP6dKuu475ZCeq+NIC15RpbbikWKtYE
HBJ7BW8XQKx67iHGx8ygHTDLbREL80Bck3oUm7wIYGMoNijD6RBl25p4gYl9dzOd
TqGl5hW/1P5hMbgEzHbr4O3BfWqU2g7tV36TASy3jbC3ONFRNNYrpEZ1AL3+cUri
OPPkKtAKAbQkKbUIfsHpBZjKZMU=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDDDCCAfSgAwIBAgIIOV5hkYJx0JwwDQYJKoZIhvcNAQELBQAwIDEeMBwGA1UE
AxMVUGViYmxlIFJvb3QgQ0EgNTBmZmJkMB4XDTE4MTEwNzE3NDY0N1oXDTQ4MTEw
NzE3NDY0N1owKDEmMCQGA1UEAxMdUGViYmxlIEludGVybWVkaWF0ZSBDQSAzOTVl
NjEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCacwXN4LmyRTgYS8TT
SZYgz758npHiPTBDKgeN5WVmkkwW0TuN4W2zXhEmcM82uxOEjWS2drvK0+iJKneh
0fQR8ZF35dIYFe8WXTg3kEmqcizSgh4LxlOntsXvatfX/6GU/ADo3xAFoBKCijen
SRBIY65yq5m00cWx3RMIcQq1B0X8nJS0O1P7MYE/Vvidz5St/36RXVu1oWLeS5Fx
HAezW0lqxEUzvC+uLTFWC6f/CilzmI7SsPAkZBk7dO5Qs0d7m/zWF588vlGS+0pt
D1on+lU85Ma2zuAd0qmB6LY66N8pEKKtMk93wF/o4Z5i58ahbwNvTKAzz4JSRWSu
mB9LAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIChDAdBgNVHSUEFjAUBggrBgEFBQcD
AQYIKwYBBQUHAwIwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEA
upU0DjzvIvoCOYKbq1RRN7rPdYad39mfjxgkeV0iOF5JoIdO6y1C7XAm9lT69Wjm
iUPvnCTMDYft40N2SvmXuuMaPOm4zjNwn4K33jw5XBnpwxC7By/Y0oV+Sl10fBsd
QqXC6H7LcSGkv+4eJbgY33P4uH5ZAy+2TkHUuZDkpufkAshzBust7nDAjfv3AIuQ
wlPoyZfI11eqyiOqRzOq+B5dIBr1JzKnEzSL6n0JLNQiPO7iN03rud/wYD3gbmcv
rzFL1KZfz+HZdnFwFW2T2gVW8L3ii1l9AJDuKzlvjUH3p6bgihVq02sjT8mx+GM2
7R4IbHGnj0BJA2vMYC4hSw==
-----END CERTIFICATE-----
`

const issuerMock = `-----BEGIN CERTIFICATE-----
MIIDDDCCAfSgAwIBAgIIOV5hkYJx0JwwDQYJKoZIhvcNAQELBQAwIDEeMBwGA1UE
AxMVUGViYmxlIFJvb3QgQ0EgNTBmZmJkMB4XDTE4MTEwNzE3NDY0N1oXDTQ4MTEw
NzE3NDY0N1owKDEmMCQGA1UEAxMdUGViYmxlIEludGVybWVkaWF0ZSBDQSAzOTVl
NjEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCacwXN4LmyRTgYS8TT
SZYgz758npHiPTBDKgeN5WVmkkwW0TuN4W2zXhEmcM82uxOEjWS2drvK0+iJKneh
0fQR8ZF35dIYFe8WXTg3kEmqcizSgh4LxlOntsXvatfX/6GU/ADo3xAFoBKCijen
SRBIY65yq5m00cWx3RMIcQq1B0X8nJS0O1P7MYE/Vvidz5St/36RXVu1oWLeS5Fx
HAezW0lqxEUzvC+uLTFWC6f/CilzmI7SsPAkZBk7dO5Qs0d7m/zWF588vlGS+0pt
D1on+lU85Ma2zuAd0qmB6LY66N8pEKKtMk93wF/o4Z5i58ahbwNvTKAzz4JSRWSu
mB9LAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIChDAdBgNVHSUEFjAUBggrBgEFBQcD
AQYIKwYBBQUHAwIwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEA
upU0DjzvIvoCOYKbq1RRN7rPdYad39mfjxgkeV0iOF5JoIdO6y1C7XAm9lT69Wjm
iUPvnCTMDYft40N2SvmXuuMaPOm4zjNwn4K33jw5XBnpwxC7By/Y0oV+Sl10fBsd
QqXC6H7LcSGkv+4eJbgY33P4uH5ZAy+2TkHUuZDkpufkAshzBust7nDAjfv3AIuQ
wlPoyZfI11eqyiOqRzOq+B5dIBr1JzKnEzSL6n0JLNQiPO7iN03rud/wYD3gbmcv
rzFL1KZfz+HZdnFwFW2T2gVW8L3ii1l9AJDuKzlvjUH3p6bgihVq02sjT8mx+GM2
7R4IbHGnj0BJA2vMYC4hSw==
-----END CERTIFICATE-----
`

func Test_checkResponse(t *testing.T) {
	server := tester.MockACMEServer().
		Route("POST /certificate", servermock.RawStringResponse(certResponseMock)).
		BuildHTTPS(t)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "Could not generate test key")

	core, err := api.New(server.Client(), "lego-test", server.URL+"/dir", "", key)
	require.NoError(t, err)

	certifier := NewCertifier(core, &resolverMock{}, CertifierOptions{})

	order := acme.ExtendedOrder{
		Order: acme.Order{
			Status:      acme.StatusValid,
			Certificate: server.URL + "/certificate",
		},
	}

	certRes := &Resource{}

	valid, err := certifier.checkResponse(t.Context(), certRes, order, true, "")
	require.NoError(t, err)
	assert.True(t, valid)
	assert.NotNil(t, certRes)
	assert.Empty(t, certRes.ID)
	assert.Empty(t, certRes.Domains)
	assert.Contains(t, certRes.CertStableURL, "/certificate")
	assert.Contains(t, certRes.CertURL, "/certificate")
	assert.Nil(t, certRes.CSR)
	assert.Nil(t, certRes.PrivateKey)
	assert.Equal(t, certResponseMock, string(certRes.Certificate), "Certificate")
	assert.Equal(t, issuerMock, string(certRes.IssuerCertificate), "IssuerCertificate")
}

func Test_checkResponse_issuerRelUp(t *testing.T) {
	server := tester.MockACMEServer().
		Route("POST /certificate", servermock.RawStringResponse(certResponseMock)).
		BuildHTTPS(t)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "Could not generate test key")

	core, err := api.New(server.Client(), "lego-test", server.URL+"/dir", "", key)
	require.NoError(t, err)

	certifier := NewCertifier(core, &resolverMock{}, CertifierOptions{})

	order := acme.ExtendedOrder{
		Order: acme.Order{
			Status:      acme.StatusValid,
			Certificate: server.URL + "/certificate",
		},
	}

	certRes := &Resource{}

	valid, err := certifier.checkResponse(t.Context(), certRes, order, true, "")
	require.NoError(t, err)
	assert.True(t, valid)
	assert.NotNil(t, certRes)
	assert.Empty(t, certRes.ID)
	assert.Empty(t, certRes.Domains)
	assert.Contains(t, certRes.CertStableURL, "/certificate")
	assert.Contains(t, certRes.CertURL, "/certificate")
	assert.Nil(t, certRes.CSR)
	assert.Nil(t, certRes.PrivateKey)
	assert.Equal(t, certResponseMock, string(certRes.Certificate), "Certificate")
	assert.Equal(t, issuerMock, string(certRes.IssuerCertificate), "IssuerCertificate")
}

func Test_checkResponse_no_bundle(t *testing.T) {
	server := tester.MockACMEServer().
		Route("POST /certificate", servermock.RawStringResponse(certResponseMock)).
		BuildHTTPS(t)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "Could not generate test key")

	core, err := api.New(server.Client(), "lego-test", server.URL+"/dir", "", key)
	require.NoError(t, err)

	certifier := NewCertifier(core, &resolverMock{}, CertifierOptions{})

	order := acme.ExtendedOrder{
		Order: acme.Order{
			Status:      acme.StatusValid,
			Certificate: server.URL + "/certificate",
		},
	}

	certRes := &Resource{}

	valid, err := certifier.checkResponse(t.Context(), certRes, order, false, "")
	require.NoError(t, err)
	assert.True(t, valid)
	assert.NotNil(t, certRes)
	assert.Empty(t, certRes.ID)
	assert.Empty(t, certRes.Domains)
	assert.Contains(t, certRes.CertStableURL, "/certificate")
	assert.Contains(t, certRes.CertURL, "/certificate")
	assert.Nil(t, certRes.CSR)
	assert.Nil(t, certRes.PrivateKey)
	assert.Equal(t, certResponseNoBundleMock, string(certRes.Certificate), "Certificate")
	assert.Equal(t, issuerMock, string(certRes.IssuerCertificate), "IssuerCertificate")
}

func Test_checkResponse_alternate(t *testing.T) {
	// The default and alternate chains share the exact same leaf certificate
	// but end at different roots. Only the alternate root CN matches the
	// preferred chain option.
	defaultChain, err := newTestChain("Pebble Root CA 50ffbd", "Pebble Intermediate CA 395e61", "acme.wtf")
	require.NoError(t, err)

	// The alternate path shares the leaf and intermediate certificates and
	// only diverges at the cross-signed root.
	alternateChain, err := defaultChain.withRoot("DST Root CA X3")
	require.NoError(t, err)

	defaultRaw := defaultChain.rawBundled()
	alternateRaw := alternateChain.rawBundled()

	server := tester.MockACMEServer().
		Route("POST /certificate",
			http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				rw.Header().Add("Link",
					fmt.Sprintf(`<https://%s/certificate/1>;title="foo";rel="alternate"`, req.Context().Value(http.LocalAddrContextKey)))

				servermock.RawResponse(defaultRaw.Cert).ServeHTTP(rw, req)
			})).
		Route("/certificate/1", servermock.RawResponse(alternateRaw.Cert)).
		BuildHTTPS(t)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "Could not generate test key")

	core, err := api.New(server.Client(), "lego-test", server.URL+"/dir", "", key)
	require.NoError(t, err)

	certifier := NewCertifier(core, &resolverMock{}, CertifierOptions{})

	order := acme.ExtendedOrder{
		Order: acme.Order{
			Status:      acme.StatusValid,
			Certificate: server.URL + "/certificate",
		},
	}

	certRes := &Resource{
		ID:      "example.com",
		Domains: []string{"example.com"},
	}

	valid, err := certifier.checkResponse(t.Context(), certRes, order, true, "DST Root CA X3")
	require.NoError(t, err)

	assert.True(t, valid)
	assert.NotNil(t, certRes)
	assert.Equal(t, "example.com", certRes.ID)
	assert.Equal(t, []string{"example.com"}, certRes.Domains)
	assert.Contains(t, certRes.CertStableURL, "/certificate/1")
	assert.Contains(t, certRes.CertURL, "/certificate/1")
	assert.Nil(t, certRes.CSR)
	assert.Nil(t, certRes.PrivateKey)
	assert.True(t, certRes.PreferredChainMatched)
	assert.Equal(t, alternateRaw.Cert, certRes.Certificate, "Certificate")
	assert.Equal(t, alternateRaw.Issuer, certRes.IssuerCertificate, "IssuerCertificate")
}

func Test_Get(t *testing.T) {
	server := tester.MockACMEServer().
		Route("POST /acme/cert/test-cert", servermock.RawStringResponse(certResponseMock)).
		BuildHTTPS(t)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "Could not generate test key")

	core, err := api.New(server.Client(), "lego-test", server.URL+"/dir", "", key)
	require.NoError(t, err)

	certifier := NewCertifier(core, &resolverMock{}, CertifierOptions{})

	certRes, err := certifier.Get(t.Context(), server.URL+"/acme/cert/test-cert", true)
	require.NoError(t, err)

	assert.NotNil(t, certRes)
	assert.Equal(t, "acme.wtf", certRes.ID)
	assert.Equal(t, []string{"acme.wtf"}, certRes.Domains)
	assert.Equal(t, server.URL+"/acme/cert/test-cert", certRes.CertStableURL)
	assert.Equal(t, server.URL+"/acme/cert/test-cert", certRes.CertURL)
	assert.Nil(t, certRes.CSR)
	assert.Nil(t, certRes.PrivateKey)
	assert.Equal(t, certResponseMock, string(certRes.Certificate), "Certificate")
	assert.Equal(t, issuerMock, string(certRes.IssuerCertificate), "IssuerCertificate")
}

func Test_checkOrderStatus(t *testing.T) {
	testCases := []struct {
		desc       string
		order      acme.Order
		requireErr require.ErrorAssertionFunc
		expected   bool
	}{
		{
			desc:       "status valid",
			order:      acme.Order{Status: acme.StatusValid},
			requireErr: require.NoError,
			expected:   true,
		},
		{
			desc:       "status invalid",
			order:      acme.Order{Status: acme.StatusInvalid},
			requireErr: require.Error,
			expected:   false,
		},
		{
			desc:       "status invalid with error",
			order:      acme.Order{Status: acme.StatusInvalid, Error: &acme.ProblemDetails{}},
			requireErr: require.Error,
			expected:   false,
		},
		{
			desc:       "unknown status",
			order:      acme.Order{Status: "foo"},
			requireErr: require.NoError,
			expected:   false,
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			status, err := checkOrderStatus(acme.ExtendedOrder{Order: test.order})
			test.requireErr(t, err)

			assert.Equal(t, test.expected, status)
		})
	}
}

type resolverMock struct {
	error error
}

func (r *resolverMock) Solve(_ context.Context, _ []acme.Authorization) error {
	return r.error
}
