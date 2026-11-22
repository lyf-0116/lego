package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/certcrypto"
	"github.com/go-acme/lego/v5/internal/tester"
	"github.com/go-acme/lego/v5/internal/tester/servermock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	ariLeafPEM = `-----BEGIN CERTIFICATE-----
MIIBQzCB66ADAgECAgUAh2VDITAKBggqhkjOPQQDAjAVMRMwEQYDVQQDEwpFeGFt
cGxlIENBMCIYDzAwMDEwMTAxMDAwMDAwWhgPMDAwMTAxMDEwMDAwMDBaMBYxFDAS
BgNVBAMTC2V4YW1wbGUuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEeBZu
7cbpAYNXZLbbh8rNIzuOoqOOtmxA1v7cRm//AwyMwWxyHz4zfwmBhcSrf47NUAFf
qzLQ2PPQxdTXREYEnKMjMCEwHwYDVR0jBBgwFoAUaYhba4dGQEHhs3uEe6CuLN4B
yNQwCgYIKoZIzj0EAwIDRwAwRAIge09+S5TZAlw5tgtiVvuERV6cT4mfutXIlwTb
+FYN/8oCIClDsqBklhB9KAelFiYt9+6FDj3z4KGVelYM5MdsO3pK
-----END CERTIFICATE-----`
	ariLeafCertID = "aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE"
)

func TestMakeCertID(t *testing.T) {
	leaf, err := certcrypto.ParsePEMCertificate([]byte(ariLeafPEM))
	require.NoError(t, err)

	actual, err := MakeARICertID(leaf)
	require.NoError(t, err)
	assert.Equal(t, ariLeafCertID, actual)
}

func TestMakeCertID_longSerialNumber(t *testing.T) {
	// The DER encoding of these serial numbers uses the long-form length octets,
	// so slicing the marshalled INTEGER at a fixed offset would include length bytes
	// (or even the tag) in the base64url digest.
	testCases := []struct {
		desc   string
		serial *big.Int
	}{
		{
			desc:   "128 content bytes with leading zero padding",
			serial: new(big.Int).SetBit(big.NewInt(0), 255, 1),
		},
		{
			desc:   "128 content bytes without leading zero padding",
			serial: new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1)),
		},
		{
			desc:   "127 content bytes",
			serial: new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(1)),
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			leaf := generateARILeaf(t, test.serial)

			actual, err := MakeARICertID(leaf)
			require.NoError(t, err)

			// Rebuild the expected identifier from the DER encoding by stripping the tag and every
			// length octet, which is exactly what RFC 9773 section 4.1 prescribes.
			der, err := asn1.Marshal(test.serial)
			require.NoError(t, err)
			require.GreaterOrEqual(t, len(der), 3)

			contentStart := 2
			if der[1]&0x80 != 0 {
				contentStart = 2 + int(der[1]&0x7f)
			}

			expectedSerial := base64.RawURLEncoding.EncodeToString(der[contentStart:])
			expectedAKI := base64.RawURLEncoding.EncodeToString(leaf.AuthorityKeyId)

			assert.Equal(t, expectedAKI+"."+expectedSerial, actual)

			// The computed identifier must not contain any length octet of the long-form encoding.
			assert.NotContains(t, actual, base64.RawURLEncoding.EncodeToString(der[1:contentStart]))
		})
	}
}

func generateARILeaf(t *testing.T, serial *big.Int) *x509.Certificate {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: serial,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"example.com"},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	leaf, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	return leaf
}

func TestCertificateService_GetRenewalInfo(t *testing.T) {
	// small value keeps test fast
	privateKey, errK := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, errK, "Could not generate test key")

	server := tester.MockACMEServer().
		Route("GET /renewalInfo/"+ariLeafCertID,
			servermock.RawStringResponse(`{
					"suggestedWindow": {
						"start": "2020-03-17T17:51:09Z",
						"end": "2020-03-17T18:21:09Z"
					},
					"explanationUrl": "https://aricapable.ca.example/docs/renewal-advice/"
				}`).
				WithHeader("Content-Type", "application/json").
				WithHeader("Retry-After", "21600")).
		BuildHTTPS(t)

	core, err := New(server.Client(), "lego-test", server.URL+"/dir", "", privateKey)
	require.NoError(t, err)

	leaf, err := certcrypto.ParsePEMCertificate([]byte(ariLeafPEM))
	require.NoError(t, err)

	ri, err := core.Certificates.GetRenewalInfo(t.Context(), mustMakeARICertID(t, leaf))
	require.NoError(t, err)
	require.NotNil(t, ri)
	assert.Equal(t, "2020-03-17T17:51:09Z", ri.SuggestedWindow.Start.Format(time.RFC3339))
	assert.Equal(t, "2020-03-17T18:21:09Z", ri.SuggestedWindow.End.Format(time.RFC3339))
	assert.Equal(t, "https://aricapable.ca.example/docs/renewal-advice/", ri.ExplanationURL)
	assert.Equal(t, time.Duration(21600000000000), ri.RetryAfter)
}

func TestCertificateService_GetRenewalInfo_retryAfter(t *testing.T) {
	leaf, err := certcrypto.ParsePEMCertificate([]byte(ariLeafPEM))
	require.NoError(t, err)

	server := tester.MockACMEServer().
		Route("GET /renewalInfo/"+ariLeafCertID,
			servermock.RawStringResponse(`{
				"suggestedWindow": {
					"start": "2020-03-17T17:51:09Z",
					"end": "2020-03-17T18:21:09Z"
				},
				"explanationUrl": "https://aricapable.ca.example/docs/renewal-advice/"
			}`).
				WithHeader("Content-Type", "application/json").
				WithHeader("Retry-After", time.Now().UTC().Add(6*time.Hour).Format(time.RFC1123))).
		BuildHTTPS(t)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "Could not generate test key")

	core, err := New(server.Client(), "lego-test", server.URL+"/dir", "", key)
	require.NoError(t, err)

	ri, err := core.Certificates.GetRenewalInfo(t.Context(), mustMakeARICertID(t, leaf))
	require.NoError(t, err)
	require.NotNil(t, ri)
	assert.Equal(t, "2020-03-17T17:51:09Z", ri.SuggestedWindow.Start.Format(time.RFC3339))
	assert.Equal(t, "2020-03-17T18:21:09Z", ri.SuggestedWindow.End.Format(time.RFC3339))
	assert.Equal(t, "https://aricapable.ca.example/docs/renewal-advice/", ri.ExplanationURL)

	assert.InDelta(t, 6, ri.RetryAfter.Hours(), 0.001)
}

func TestCertificateService_GetRenewalInfo_errors(t *testing.T) {
	leaf, err := certcrypto.ParsePEMCertificate([]byte(ariLeafPEM))
	require.NoError(t, err)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "Could not generate test key")

	testCases := []struct {
		desc        string
		timeout     time.Duration
		request     string
		handler     http.HandlerFunc
		expectedErr error
	}{
		{
			desc:    "API timeout",
			timeout: 500 * time.Millisecond, // HTTP client that times out after 500ms.
			request: mustMakeARICertID(t, leaf),
			handler: func(w http.ResponseWriter, r *http.Request) {
				// API that takes 2ms to respond.
				time.Sleep(2 * time.Millisecond)
			},
		},
		{
			desc:    "API error",
			request: mustMakeARICertID(t, leaf),
			handler: func(w http.ResponseWriter, r *http.Request) {
				// API that responds with error instead of renewal info.
				http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			},
		},
		{
			desc:        "end before start",
			request:     mustMakeARICertID(t, leaf),
			expectedErr: ErrInvalidWindow,
			handler: func(w http.ResponseWriter, r *http.Request) {
				info := &acme.RenewalInfo{
					SuggestedWindow: acme.Window{
						Start: time.Now(),
						End:   time.Now().Add(-time.Hour),
					},
				}

				_ = json.NewEncoder(w).Encode(info)
			},
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			server := tester.MockACMEServer().
				Route("GET /renewalInfo/"+ariLeafCertID, test.handler).
				BuildHTTPS(t)

			client := server.Client()

			if test.timeout != 0 {
				client.Timeout = test.timeout
			}

			core, err := New(client, "lego-test", server.URL+"/dir", "", key)
			require.NoError(t, err)

			response, err := core.Certificates.GetRenewalInfo(t.Context(), test.request)
			require.Error(t, err)
			assert.Nil(t, response)

			if test.expectedErr != nil {
				assert.ErrorIs(t, err, test.expectedErr)
				assert.NotErrorIs(t, err, ErrNoARI)
			}
		})
	}
}

func mustMakeARICertID(t *testing.T, leaf *x509.Certificate) string {
	t.Helper()

	certID, err := MakeARICertID(leaf)
	require.NoError(t, err)

	return certID
}
