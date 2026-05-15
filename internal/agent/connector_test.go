package agent

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBuildTLSConfig_NoCA(t *testing.T) {
	c := NewConnector("localhost:8080", true, "", false, nil)

	cfg, err := c.buildTLSConfig()
	if err != nil {
		t.Fatalf("buildTLSConfig returned error: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil tls config")
	}
	if cfg.RootCAs != nil {
		t.Fatal("expected nil RootCAs when no custom CA is configured")
	}
}

func TestBuildTLSConfig_InsecureSkipVerify(t *testing.T) {
	c := NewConnector("localhost:8080", true, "", true, nil)

	cfg, err := c.buildTLSConfig()
	if err != nil {
		t.Fatalf("buildTLSConfig returned error: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil tls config")
	}
	if !cfg.InsecureSkipVerify {
		t.Fatal("expected InsecureSkipVerify to be true")
	}
}

func TestBuildTLSConfig_MissingCAFile(t *testing.T) {
	c := NewConnector("localhost:8080", true, filepath.Join(t.TempDir(), "missing-ca.pem"), false, nil)

	_, err := c.buildTLSConfig()
	if err == nil {
		t.Fatal("expected error for missing CA file")
	}
}

func TestBuildTLSConfig_InvalidCAFile(t *testing.T) {
	dir := t.TempDir()
	caPath := filepath.Join(dir, "invalid-ca.pem")
	if err := os.WriteFile(caPath, []byte("not a pem"), 0o600); err != nil {
		t.Fatalf("failed to write invalid CA file: %v", err)
	}

	c := NewConnector("localhost:8080", true, caPath, false, nil)

	_, err := c.buildTLSConfig()
	if err == nil {
		t.Fatal("expected error for invalid CA file")
	}
}

func TestBuildTLSConfig_ValidCAFile(t *testing.T) {
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caPath, generateTestCACertPEM(t), 0o600); err != nil {
		t.Fatalf("failed to write CA file: %v", err)
	}

	c := NewConnector("localhost:8080", true, caPath, false, nil)

	cfg, err := c.buildTLSConfig()
	if err != nil {
		t.Fatalf("buildTLSConfig returned error: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil tls config")
	}
	if cfg.RootCAs == nil {
		t.Fatal("expected RootCAs to be populated")
	}
}

func TestBuildRegisterReauthPayloadIncludesDHPubkey(t *testing.T) {
	dir := t.TempDir()
	identity, err := CreateIdentity(dir, "example:8080")
	if err != nil {
		t.Fatalf("CreateIdentity: %v", err)
	}

	c := NewConnector("example:8080", false, "", false, identity)
	payload, err := c.buildRegisterReauthPayload("client-test", time.Now().Unix(), "host", "linux")
	if err != nil {
		t.Fatalf("buildRegisterReauthPayload: %v", err)
	}

	if !payload.ReAuth {
		t.Fatal("expected reauth payload")
	}
	if payload.DevicePubkey == "" {
		t.Fatal("expected device signing public key")
	}
	if payload.DeviceDHPubkey == "" {
		t.Fatal("expected device DH public key for encrypted approval fallback")
	}
	if payload.Signature == "" {
		t.Fatal("expected reauth signature")
	}
}

func generateTestCACertPEM(t *testing.T) []byte {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test-ca",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create test certificate: %v", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
