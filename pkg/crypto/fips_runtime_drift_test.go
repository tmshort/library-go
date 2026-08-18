package crypto

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	configv1 "github.com/openshift/api/config/v1"
)

// selfSignedP256Cert returns a throwaway ECDSA P-256 server certificate. P-256
// + SHA-256 is FIPS-approved, so the cert itself is usable under fips140=on.
func selfSignedP256Cert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Unix(0, 0),
		NotAfter:     time.Unix(1<<31, 0),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// canNegotiateGroup forces both peers to offer ONLY curve at TLS 1.3 and reports
// whether the handshake completes in the current process's FIPS mode.
func canNegotiateGroup(t *testing.T, cert tls.Certificate, curve tls.CurveID) error {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates:     []tls.Certificate{cert},
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{curve},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if cerr := ln.Close(); cerr != nil {
			t.Logf("listener close: %v", cerr)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	serverResult := make(chan error, 1)
	go func() {
		conn, aerr := ln.Accept()
		if aerr != nil {
			serverResult <- aerr
			return
		}
		hsErr := conn.(*tls.Conn).HandshakeContext(ctx)
		// Close before signaling completion so the goroutine is fully done by the
		// time the caller reads serverResult, and never call t.Logf here: it could
		// otherwise run after the test function has returned and panic. The close
		// error is irrelevant to the drift assertion, so it is ignored.
		_ = conn.Close()
		serverResult <- hsErr
	}()

	dialer := &tls.Dialer{
		Config: &tls.Config{
			// InsecureSkipVerify is intentional: this test uses a self-signed
			// certificate generated in-process solely to drive a TLS 1.3
			// handshake against localhost and observe which curves succeed.
			InsecureSkipVerify: true, //nolint:gosec
			MinVersion:         tls.VersionTLS13,
			CurvePreferences:   []tls.CurveID{curve},
		},
	}
	conn, err := dialer.DialContext(ctx, "tcp", ln.Addr().String())
	if err != nil {
		return err
	}
	// Wait for the server goroutine to finish before closing the client
	// connection, so we capture any server-side handshake error.
	serverErr := <-serverResult
	if cerr := conn.Close(); cerr != nil {
		t.Logf("client conn close: %v", cerr)
	}
	return serverErr
}

// TestFIPSApprovalMatchesRuntime is a drift guard between OpenShift's static
// FIPS allowlist (fips.go) and what the Go toolchain actually negotiates. It
// runs real TLS 1.3 handshakes in whatever FIPS mode the test binary is in, so
// the FIPS-specific assertions only execute under `GODEBUG=fips140=on`.
//
// See the "KNOWN DIVERGENCE" note in fips.go: the allowlist is intentionally
// stricter than Go's native FIPS module on X25519MLKEM768. This test pins that
// reality so a toolchain bump (or an allowlist edit) forces a conscious
// re-evaluation instead of silently drifting.
func TestFIPSApprovalMatchesRuntime(t *testing.T) {
	cert := selfSignedP256Cert(t)

	// Invariant in ALL modes: every group we advertise as FIPS-approved must
	// actually be negotiable by this Go build. If not, our allowlist is lying.
	for _, g := range []configv1.TLSGroup{
		configv1.TLSGroupSecP256r1,
		configv1.TLSGroupSecP384r1,
		configv1.TLSGroupSecP521r1,
	} {
		if !IsFIPSApprovedTLSGroup(g) {
			t.Errorf("expected %q to be FIPS-approved", g)
		}
		id, ok := TLSGroupToCurveID(g)
		if !ok {
			t.Errorf("FIPS-approved group %q has no Go CurveID mapping", g)
			continue
		}
		if err := canNegotiateGroup(t, cert, id); err != nil {
			t.Errorf("FIPS-approved group %q is not negotiable by this Go build: %v", g, err)
		}
	}

	if !IsFIPSEnabled() {
		t.Skip("FIPS-specific drift checks require GODEBUG=fips140=on (exercised by the FIPS CI lane)")
	}

	// FIPS-mode sanity: plain X25519 is not approved, and Go's FIPS module must
	// refuse it. This confirms the runtime is genuinely filtering curves. A
	// missing mapping is a hard failure, not a silent skip: otherwise removing
	// the curve from the map would quietly disable this drift assertion.
	x25519, ok := TLSGroupToCurveID(configv1.TLSGroupX25519)
	if !ok {
		t.Fatalf("X25519 lost its CurveID mapping; the drift guard can no longer assert FIPS refusal")
	}
	if err := canNegotiateGroup(t, cert, x25519); err == nil {
		t.Errorf("X25519 negotiated under FIPS, but it is not FIPS-approved; runtime behavior changed, revisit fips.go")
	}

	// DOCUMENTED DIVERGENCE: Go negotiates X25519MLKEM768 under FIPS even though
	// our allowlist excludes it. Assert both halves so either changing forces a
	// review of the fips.go policy and the native Go FIPS adoption decision. As
	// above, a missing mapping fails hard rather than silently skipping.
	if IsFIPSApprovedTLSGroup(configv1.TLSGroupX25519MLKEM768) {
		t.Fatalf("allowlist now approves X25519MLKEM768; reconcile fips.go docs and this drift guard")
	}
	mlkem, ok := TLSGroupToCurveID(configv1.TLSGroupX25519MLKEM768)
	if !ok {
		t.Fatalf("X25519MLKEM768 lost its CurveID mapping; the drift guard can no longer assert the divergence")
	}
	if err := canNegotiateGroup(t, cert, mlkem); err != nil {
		t.Errorf("X25519MLKEM768 is no longer negotiable under FIPS (%v); the documented Go-vs-allowlist divergence changed, revisit fips.go", err)
	}
}
