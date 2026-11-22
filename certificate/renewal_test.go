package certificate

import (
	"crypto/x509"
	"math/big"
	"testing"
	"time"

	"github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/certcrypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRenewalInfoResponse_ShouldRenew(t *testing.T) {
	now := time.Now().UTC()

	leaf := &x509.Certificate{SerialNumber: big.NewInt(42)}

	t.Run("Window is in the past", func(t *testing.T) {
		ri := RenewalInfo{
			ExtendedRenewalInfo: &acme.ExtendedRenewalInfo{
				RenewalInfo: acme.RenewalInfo{
					SuggestedWindow: acme.Window{
						Start: now.Add(-2 * time.Hour),
						End:   now.Add(-1 * time.Hour),
					},
					ExplanationURL: "",
				},
				RetryAfter: 0,
			},
		}

		rt := ri.ShouldRenewAt(now, 0, leaf)
		require.NotNil(t, rt)
		assert.Equal(t, now, *rt)
	})

	t.Run("Window is in the future", func(t *testing.T) {
		ri := RenewalInfo{
			ExtendedRenewalInfo: &acme.ExtendedRenewalInfo{
				RenewalInfo: acme.RenewalInfo{
					SuggestedWindow: acme.Window{
						Start: now.Add(1 * time.Hour),
						End:   now.Add(2 * time.Hour),
					},
					ExplanationURL: "",
				},
				RetryAfter: 0,
			},
		}

		rt := ri.ShouldRenewAt(now, 0, leaf)
		assert.Nil(t, rt)
	})

	t.Run("Window is in the future, but caller is willing to sleep", func(t *testing.T) {
		ri := RenewalInfo{
			ExtendedRenewalInfo: &acme.ExtendedRenewalInfo{
				RenewalInfo: acme.RenewalInfo{
					SuggestedWindow: acme.Window{
						Start: now.Add(1 * time.Hour),
						End:   now.Add(2 * time.Hour),
					},
					ExplanationURL: "",
				},
				RetryAfter: 0,
			},
		}

		rt := ri.ShouldRenewAt(now, 2*time.Hour, leaf)
		require.NotNil(t, rt)
		assert.True(t, rt.Before(now.Add(2*time.Hour)))
	})

	t.Run("Window is in the future, but caller isn't willing to sleep long enough", func(t *testing.T) {
		ri := RenewalInfo{
			ExtendedRenewalInfo: &acme.ExtendedRenewalInfo{
				RenewalInfo: acme.RenewalInfo{
					SuggestedWindow: acme.Window{
						Start: now.Add(1 * time.Hour),
						End:   now.Add(2 * time.Hour),
					},
					ExplanationURL: "",
				},
				RetryAfter: 0,
			},
		}

		rt := ri.ShouldRenewAt(now, 59*time.Minute, leaf)
		assert.Nil(t, rt)
	})
}

func TestRenewalInfoResponse_ShouldRenewAt_deterministic(t *testing.T) {
	now := time.Now().UTC()

	newInfo := func(start, end time.Time) *RenewalInfo {
		return &RenewalInfo{
			ExtendedRenewalInfo: &acme.ExtendedRenewalInfo{
				RenewalInfo: acme.RenewalInfo{
					SuggestedWindow: acme.Window{Start: start, End: end},
				},
			},
		}
	}

	t.Run("same certificate and same window always pick the same point", func(t *testing.T) {
		ri := newInfo(now.Add(time.Hour), now.Add(3*time.Hour))
		leaf := &x509.Certificate{SerialNumber: big.NewInt(123456789)}

		first := ri.ShouldRenewAt(now, 10*time.Hour, leaf)
		require.NotNil(t, first)

		for range 10 {
			next := ri.ShouldRenewAt(now, 10*time.Hour, leaf)
			require.NotNil(t, next)
			assert.Equal(t, *first, *next)
		}
	})

	t.Run("point always stays within the window", func(t *testing.T) {
		start := now.Add(time.Hour)
		end := now.Add(3 * time.Hour)
		ri := newInfo(start, end)

		for i := range 50 {
			leaf := &x509.Certificate{SerialNumber: big.NewInt(int64(i))}

			rt := ri.ShouldRenewAt(now, 10*time.Hour, leaf)
			require.NotNil(t, rt)
			assert.False(t, rt.Before(start), "renewal time %s before window start %s", rt, start)
			assert.True(t, rt.Before(end), "renewal time %s at or after window end %s", rt, end)
		}
	})

	t.Run("distinct certificates spread across the window", func(t *testing.T) {
		start := now.Add(time.Hour)
		end := now.Add(2 * time.Hour)
		ri := newInfo(start, end)

		seen := make(map[time.Time]struct{})

		for i := range 20 {
			leaf := &x509.Certificate{SerialNumber: big.NewInt(int64(i))}

			rt := ri.ShouldRenewAt(now, 10*time.Hour, leaf)
			require.NotNil(t, rt)
			seen[*rt] = struct{}{}
		}

		assert.Greater(t, len(seen), 1, "the fleet must not collapse onto a single renewal point")
	})

	t.Run("sliding window yields a new point", func(t *testing.T) {
		leaf := &x509.Certificate{SerialNumber: big.NewInt(987654321)}

		firstWindow := newInfo(now.Add(time.Hour), now.Add(2*time.Hour))
		first := firstWindow.ShouldRenewAt(now, 10*time.Hour, leaf)
		require.NotNil(t, first)

		// The server slides the window to a later range on the next ARI poll.
		slidWindow := newInfo(now.Add(2*time.Hour), now.Add(3*time.Hour))
		slid := slidWindow.ShouldRenewAt(now, 10*time.Hour, leaf)
		require.NotNil(t, slid)

		assert.NotEqual(t, *first, *slid)
	})

	t.Run("nil certificate remains deterministic", func(t *testing.T) {
		ri := newInfo(now.Add(time.Hour), now.Add(2*time.Hour))

		first := ri.ShouldRenewAt(now, 10*time.Hour, nil)
		require.NotNil(t, first)

		next := ri.ShouldRenewAt(now, 10*time.Hour, nil)
		require.NotNil(t, next)
		assert.Equal(t, *first, *next)
	})
}

func Test_newRenewRequest(t *testing.T) {
	testCases := []struct {
		desc     string
		certRes  Resource
		x509Cert *x509.Certificate
		options  *RenewOptions

		expected ObtainRequest
	}{
		{
			desc:     "empty",
			certRes:  Resource{},
			x509Cert: &x509.Certificate{},
			options:  &RenewOptions{},

			expected: ObtainRequest{},
		},
		{
			desc: "key type on resource",
			certRes: Resource{
				KeyType: certcrypto.EC256,
			},
			x509Cert: &x509.Certificate{
				DNSNames: []string{"example.com", "example.org"},
			},
			options: &RenewOptions{},
			expected: ObtainRequest{
				Domains: []string{"example.com", "example.org"},
				KeyType: certcrypto.EC256,
			},
		},
		{
			desc:    "key type options",
			certRes: Resource{},
			x509Cert: &x509.Certificate{
				DNSNames: []string{"example.com", "example.org"},
			},
			options: &RenewOptions{
				KeyType: certcrypto.EC256,
			},
			expected: ObtainRequest{
				Domains: []string{"example.com", "example.org"},
				KeyType: certcrypto.EC256,
			},
		},
		{
			desc: "key type on resource and key type options",
			certRes: Resource{
				KeyType: certcrypto.RSA2048,
			},
			x509Cert: &x509.Certificate{
				DNSNames: []string{"example.com", "example.org"},
			},
			options: &RenewOptions{
				KeyType: certcrypto.EC256,
			},
			expected: ObtainRequest{
				Domains: []string{"example.com", "example.org"},
				KeyType: certcrypto.EC256,
			},
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			request, err := newRenewRequest(test.certRes, test.x509Cert, test.options)
			require.NoError(t, err)

			assert.Equal(t, test.expected, request)
		})
	}
}
