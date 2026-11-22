package certificate

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/acme/api"
	"github.com/go-acme/lego/v5/internal/tester"
	"github.com/go-acme/lego/v5/internal/tester/servermock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	defaultRootCN   = "Pebble Root CA 50ffbd"
	preferredRootCN = "DST Root CA X3"
	otherRootCN     = "ISRG Root X1"
)

type preferredChainFixture struct {
	certifier *Certifier
	order     acme.ExtendedOrder
}

func newCertifierFromServer(t *testing.T, server *httptest.Server) *Certifier {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "Could not generate test key")

	core, err := api.New(server.Client(), "lego-test", server.URL+"/dir", "", key)
	require.NoError(t, err)

	return NewCertifier(core, &resolverMock{}, CertifierOptions{})
}

func newPreferredChainFixture(t *testing.T, routes map[string]*acme.RawCertificate) *preferredChainFixture {
	t.Helper()

	builder := tester.MockACMEServer()

	builder.Route("POST /certificate", http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		links := make([]string, 0, len(routes)-1)

		for link := range routes {
			if link != "/certificate" {
				links = append(links, link)
			}
		}

		for _, link := range links {
			rw.Header().Add("Link",
				fmt.Sprintf(`<https://%s%s>;rel="alternate"`, req.Context().Value(http.LocalAddrContextKey), link))
		}

		servermock.RawResponse(routes["/certificate"].Cert).ServeHTTP(rw, req)
	}))

	for link, raw := range routes {
		if link != "/certificate" {
			builder.Route(link, servermock.RawResponse(raw.Cert))
		}
	}

	server := builder.BuildHTTPS(t)

	return &preferredChainFixture{
		certifier: newCertifierFromServer(t, server),
		order: acme.ExtendedOrder{
			Order: acme.Order{
				Status:      acme.StatusValid,
				Certificate: server.URL + "/certificate",
			},
		},
	}
}

func Test_checkResponse_preferredChain_defaultMatches(t *testing.T) {
	chain, err := newTestChain(preferredRootCN, "Pebble Intermediate CA 395e61", "acme.wtf")
	require.NoError(t, err)

	server := tester.MockACMEServer().
		Route("POST /certificate", servermock.RawResponse(chain.rawBundled().Cert)).
		BuildHTTPS(t)

	certifier := newCertifierFromServer(t, server)

	certRes := &Resource{}

	valid, err := certifier.checkResponse(t.Context(), certRes, acme.ExtendedOrder{
		Order: acme.Order{Status: acme.StatusValid, Certificate: server.URL + "/certificate"},
	}, true, preferredRootCN)
	require.NoError(t, err)
	assert.True(t, valid)
	assert.True(t, certRes.PreferredChainMatched)
	assert.Equal(t, server.URL+"/certificate", certRes.CertURL)
}

func Test_checkResponse_preferredChain_noMatchKeepsDefault(t *testing.T) {
	defaultChain, err := newTestChain(defaultRootCN, "Pebble Intermediate CA 395e61", "acme.wtf")
	require.NoError(t, err)

	alternateChain, err := defaultChain.withRoot(otherRootCN)
	require.NoError(t, err)

	routes := map[string]*acme.RawCertificate{
		"/certificate":   defaultChain.rawBundled(),
		"/certificate/1": alternateChain.rawBundled(),
	}

	fixture := newPreferredChainFixture(t, routes)

	certRes := &Resource{}

	valid, err := fixture.certifier.checkResponse(t.Context(), certRes, fixture.order, true, preferredRootCN)
	require.NoError(t, err)
	assert.True(t, valid)
	assert.False(t, certRes.PreferredChainMatched, "no chain should match the preferred root")
	assert.Equal(t, routes["/certificate"].Cert, certRes.Certificate)
	assert.Equal(t, routes["/certificate"].Issuer, certRes.IssuerCertificate)
}

func Test_checkResponse_preferredChain_leafMismatchRejected(t *testing.T) {
	defaultChain, err := newTestChain(defaultRootCN, "Pebble Intermediate CA 395e61", "acme.wtf")
	require.NoError(t, err)

	// The alternate chain ends at the preferred root but has a different leaf
	// certificate, so it must not be selected.
	alternateChain, err := newTestChain(preferredRootCN, "Let's Encrypt Authority X3", "other.example")
	require.NoError(t, err)

	routes := map[string]*acme.RawCertificate{
		"/certificate":   defaultChain.rawBundled(),
		"/certificate/1": alternateChain.rawBundled(),
	}

	fixture := newPreferredChainFixture(t, routes)

	certRes := &Resource{}

	valid, err := fixture.certifier.checkResponse(t.Context(), certRes, fixture.order, true, preferredRootCN)
	require.NoError(t, err)
	assert.True(t, valid)
	assert.False(t, certRes.PreferredChainMatched)
	assert.Equal(t, routes["/certificate"].Cert, certRes.Certificate)
}

func Test_checkResponse_preferredChain_brokenLinkRejected(t *testing.T) {
	defaultChain, err := newTestChain(defaultRootCN, "Pebble Intermediate CA 395e61", "acme.wtf")
	require.NoError(t, err)

	alternateChain, err := defaultChain.withRoot(preferredRootCN)
	require.NoError(t, err)

	raw := alternateChain.rawBundled()

	// Swap the intermediate and root positions: the leaf is no longer chained
	// to the next certificate through matching issuer/subject names.
	shuffledIssuer := pemChain(alternateChain.root, alternateChain.intermediate)
	raw.Cert = append(pemChain(alternateChain.leaf), shuffledIssuer...)
	raw.Issuer = shuffledIssuer

	routes := map[string]*acme.RawCertificate{
		"/certificate":   defaultChain.rawBundled(),
		"/certificate/1": raw,
	}

	fixture := newPreferredChainFixture(t, routes)

	certRes := &Resource{}

	valid, err := fixture.certifier.checkResponse(t.Context(), certRes, fixture.order, true, preferredRootCN)
	require.NoError(t, err)
	assert.True(t, valid)
	assert.False(t, certRes.PreferredChainMatched)
	assert.Equal(t, routes["/certificate"].Cert, certRes.Certificate)
}

func Test_checkResponse_preferredChain_deterministicSelection(t *testing.T) {
	defaultChain, err := newTestChain(defaultRootCN, "Pebble Intermediate CA 395e61", "acme.wtf")
	require.NoError(t, err)

	firstMatch, err := defaultChain.withRoot(preferredRootCN)
	require.NoError(t, err)

	secondMatch, err := defaultChain.withRoot(preferredRootCN)
	require.NoError(t, err)

	routes := map[string]*acme.RawCertificate{
		"/certificate":   defaultChain.rawBundled(),
		"/certificate/1": firstMatch.rawBundled(),
		"/certificate/2": secondMatch.rawBundled(),
	}

	fixture := newPreferredChainFixture(t, routes)

	for range 10 {
		certRes := &Resource{}

		valid, err := fixture.certifier.checkResponse(t.Context(), certRes, fixture.order, true, preferredRootCN)
		require.NoError(t, err)
		require.True(t, valid)
		assert.True(t, certRes.PreferredChainMatched)
		assert.Contains(t, certRes.CertURL, "/certificate/1")
	}
}

func Test_isPreferredChain_nonBundled(t *testing.T) {
	defaultChain, err := newTestChain(defaultRootCN, "Pebble Intermediate CA 395e61", "acme.wtf")
	require.NoError(t, err)

	alternateChain, err := defaultChain.withRoot(preferredRootCN)
	require.NoError(t, err)

	defaultRaw := defaultChain.rawSplit()
	alternateRaw := alternateChain.rawSplit()

	defaultParsed, err := parseCertificateChain(defaultRaw)
	require.NoError(t, err)

	alternateParsed, err := parseCertificateChain(alternateRaw)
	require.NoError(t, err)

	assert.True(t, isPreferredChain(defaultParsed[0], alternateParsed, preferredRootCN))
	assert.False(t, isPreferredChain(defaultParsed[0], alternateParsed, defaultRootCN))
	assert.Len(t, alternateParsed, 3)
}

func Test_isPreferredChain(t *testing.T) {
	chain, err := newTestChain(preferredRootCN, "Pebble Intermediate CA 395e61", "acme.wtf")
	require.NoError(t, err)

	parsed, err := parseCertificateChain(chain.rawBundled())
	require.NoError(t, err)

	assert.True(t, isPreferredChain(parsed[0], parsed, preferredRootCN))
	assert.False(t, isPreferredChain(parsed[0], parsed, defaultRootCN))

	otherChain, err := newTestChain(defaultRootCN, "Pebble Intermediate CA 395e61", "other.example")
	require.NoError(t, err)

	otherParsed, err := parseCertificateChain(otherChain.rawBundled())
	require.NoError(t, err)

	assert.False(t, isPreferredChain(parsed[0], otherParsed, preferredRootCN))
}

func Test_isOrderedChain(t *testing.T) {
	chain, err := newTestChain(preferredRootCN, "Pebble Intermediate CA 395e61", "acme.wtf")
	require.NoError(t, err)

	ordered := []*x509.Certificate{chain.leaf.cert, chain.intermediate.cert, chain.root.cert}
	assert.True(t, isOrderedChain(ordered))

	shuffled := []*x509.Certificate{chain.leaf.cert, chain.root.cert, chain.intermediate.cert}
	assert.False(t, isOrderedChain(shuffled))

	assert.True(t, isOrderedChain([]*x509.Certificate{chain.root.cert}))
}
