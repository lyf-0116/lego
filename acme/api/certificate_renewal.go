package api

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"

	"github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/acme/api/internal/sender"
)

// ErrNoARI is returned when the server does not advertise a renewal info endpoint.
var ErrNoARI = errors.New("renewalInfo[get/post]: server does not advertise a renewal info endpoint")

// ErrInvalidWindow is returned when the server serves a RenewalInfo object whose suggested window is invalid
// (the end timestamp equals or precedes the start timestamp).
// This is a transient server-side problem: clients MUST treat it as though they failed to receive any response,
// and retry at an appropriate interval instead of permanently falling back to a static renewal schedule.
// https://www.rfc-editor.org/rfc/rfc9773.html#section-4.2
var ErrInvalidWindow = errors.New("renewalInfo[get]: invalid suggested window: end is equal to or before start")

// GetRenewalInfo GETs renewal information for a certificate from the renewalInfo endpoint.
// This is used to determine if a certificate needs to be renewed.
//
// Note: this endpoint is part of a draft specification, not all ACME servers will implement it.
// This method will return api.ErrNoARI if the server does not advertise a renewal info endpoint.
// It will return api.ErrInvalidWindow if the served suggested window is invalid (end equal to or before start),
// which must be handled as a transient failure and retried rather than as an unsupported endpoint.
//
// https://www.rfc-editor.org/rfc/rfc9773.html
func (c *CertificateService) GetRenewalInfo(ctx context.Context, certID string) (*acme.ExtendedRenewalInfo, error) {
	if c.core.GetDirectory().RenewalInfo == "" {
		return nil, ErrNoARI
	}

	if certID == "" {
		return nil, errors.New("renewalInfo[get]: 'certID' cannot be empty")
	}

	info := new(acme.ExtendedRenewalInfo)

	resp, err := c.core.doer.Get(ctx, c.core.GetDirectory().RenewalInfo+"/"+certID, info)
	if err != nil {
		return nil, err
	}

	// A RenewalInfo object in which the end timestamp equals or precedes the start timestamp is invalid.
	// Servers MUST NOT serve such a response,
	// and clients MUST treat one as though they failed to receive any response from the server
	// (e.g., retry at an appropriate interval, renew on a fallback schedule, etc.).
	// https://www.rfc-editor.org/info/rfc9773/#section-4.2
	if info.SuggestedWindow.End.Equal(info.SuggestedWindow.Start) || info.SuggestedWindow.End.Before(info.SuggestedWindow.Start) {
		return nil, ErrInvalidWindow
	}

	info.RetryAfter = sender.GetRetryAfter(resp)

	return info, nil
}

// MakeARICertID constructs a certificate identifier as described in RFC 9773, section 4.1.
func MakeARICertID(leaf *x509.Certificate) (string, error) {
	if leaf == nil {
		return "", errors.New("leaf certificate is nil")
	}

	// Extract the content bytes of the DER encoded INTEGER value of the serial number.
	// The serial number is encoded as an ASN.1 INTEGER whose length may use the long form
	// (one or more length bytes) when the value is large, so the content does not always start
	// at a fixed offset. Decoding the whole value instead of slicing at a hard-coded offset
	// keeps the identifier correct regardless of the length encoding.
	serialContent, err := marshalARISerialNumber(leaf.SerialNumber)
	if err != nil {
		return "", err
	}

	serial := base64.RawURLEncoding.EncodeToString(serialContent)

	// Convert the Authority Key Identifier to base64url encoding without
	// padding.
	aki := base64.RawURLEncoding.EncodeToString(leaf.AuthorityKeyId)

	// Construct the final identifier by concatenating AKI and Serial Number.
	return fmt.Sprintf("%s.%s", aki, serial), nil
}

// marshalARISerialNumber returns the DER content bytes of the ASN.1 INTEGER encoding of the serial number,
// as required by RFC 9773 section 4.1: the base64url encoding of the DER serial number field without the tag
// and length octets.
func marshalARISerialNumber(serialNumber *big.Int) ([]byte, error) {
	if serialNumber == nil {
		return nil, errors.New("leaf certificate has no serial number")
	}

	// big.Int.FillBytes emits the minimal big-endian representation of the absolute value,
	// but panics on an undersized buffer, so allocate exactly the number of bytes it needs.
	content := make([]byte, (serialNumber.BitLen()+7)/8)
	if len(content) == 0 {
		return nil, errors.New("invalid DER encoding of serial number")
	}
	serialNumber.FillBytes(content)

	// A DER INTEGER is encoded in two's complement, so a positive value whose leading byte has its
	// high bit set must be prefixed with a 0x00 padding octet to keep it positive.
	if content[0]&0x80 != 0 {
		content = append([]byte{0x00}, content...)
	}

	return content, nil
}
