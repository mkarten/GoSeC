package utils

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/hashicorp/vault/shamir"
	"github.com/spf13/cobra"
	"math/big"
	"os"
	"strings"
	"time"
)

// NewSerialNumber creates a random 128-bit serial number as a *big.Int
func NewSerialNumber() (*big.Int, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}
	return serialNumber, nil
}

// BuildSubject returns a pkix.Name based on Cobra flags for subject attributes.
func BuildSubject(cmd *cobra.Command) (pkix.Name, error) {
	cn, _ := cmd.Flags().GetString("cn")
	org, _ := cmd.Flags().GetString("org")
	ou, _ := cmd.Flags().GetString("ou")
	locality, _ := cmd.Flags().GetString("locality")
	province, _ := cmd.Flags().GetString("province")
	country, _ := cmd.Flags().GetString("country")

	if cn == "" {
		return pkix.Name{}, errors.New("common name (CN) is required")
	}

	var subject pkix.Name

	if org != "" {
		subject.Organization = []string{org}
	}
	if ou != "" {
		subject.OrganizationalUnit = []string{ou}
	}
	if locality != "" {
		subject.Locality = []string{locality}
	}
	if province != "" {
		subject.Province = []string{province}
	}
	if country != "" {
		subject.Country = []string{country}
	}
	subject.CommonName = cn
	return subject, nil
}

// GenerateKeyAndCert generates an ECDSA key and a certificate (self-signed or signed by a parent).
func GenerateKeyAndCert(
	subject pkix.Name,
	parentCert *x509.Certificate,
	parentKey *ecdsa.PrivateKey,
	isCA bool,
	validityDays int,
	keyUsage x509.KeyUsage,
) ([]byte, *ecdsa.PrivateKey, error) {

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate ECDSA key: %w", err)
	}

	serialNumber, err := NewSerialNumber()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(time.Duration(validityDays) * 24 * time.Hour)

	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  isCA,
		BasicConstraintsValid: true,
	}

	// If it's a CA, automatically add CertSign to keyUsage.
	if isCA {
		keyUsage |= x509.KeyUsageCertSign
		template.MaxPathLenZero = false
		template.MaxPathLen = 1
	}
	template.KeyUsage = keyUsage

	// Self-signed if parentCert/key is nil
	var certBytes []byte
	if parentCert == nil || parentKey == nil {
		certBytes, err = x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create self-signed certificate: %w", err)
		}
	} else {
		certBytes, err = x509.CreateCertificate(rand.Reader, &template, parentCert, &priv.PublicKey, parentKey)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create certificate: %w", err)
		}
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	return certPEM, priv, nil
}

// ParseCertificateFromFile reads a PEM certificate from file and returns *x509.Certificate
func ParseCertificateFromFile(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("unable to read certificate file '%s': %w", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("failed to decode PEM block containing certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse x509 certificate: %w", err)
	}
	return cert, nil
}

// WriteCertificateToFile writes a PEM certificate to the specified file
func WriteCertificateToFile(certPEM []byte, outPath string) error {
	return os.WriteFile(outPath, certPEM, 0644)
}

// WriteECPrivateKeyToFile writes an ECDSA private key to a file in PEM format (type: "EC PRIVATE KEY").
func WriteECPrivateKeyToFile(privKey *ecdsa.PrivateKey, outPath string) error {
	keyBytes, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return fmt.Errorf("failed to marshal ECDSA private key: %w", err)
	}
	block := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyBytes,
	}
	pemBytes := pem.EncodeToMemory(block)
	return os.WriteFile(outPath, pemBytes, 0600)
}

// CombineSharesFromFiles reconstructs the private key bytes from multiple share files
func CombineSharesFromFiles(paths []string) ([]byte, error) {
	var shares [][]byte
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("cannot read share file '%s': %w", path, err)
		}
		decoded, err := base64.StdEncoding.DecodeString(string(raw))
		if err != nil {
			return nil, fmt.Errorf("failed to decode base64 from '%s': %w", path, err)
		}
		shares = append(shares, decoded)
	}
	keyBytes, err := shamir.Combine(shares)
	if err != nil {
		return nil, fmt.Errorf("shamir combine error: %w", err)
	}
	return keyBytes, nil
}

// SplitKeyAndWriteShares splits a private key into N shares with threshold T, writes each share to disk
func SplitKeyAndWriteShares(privKey *ecdsa.PrivateKey, n, t int, sharePaths []string) error {
	if len(sharePaths) != n {
		return fmt.Errorf("number of share paths (%d) does not match n=%d", len(sharePaths), n)
	}

	keyBytes, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return fmt.Errorf("failed to marshal ECDSA private key: %w", err)
	}

	shares, err := shamir.Split(keyBytes, n, t)
	if err != nil {
		return fmt.Errorf("shamir split error: %w", err)
	}

	for i, s := range shares {
		b64 := base64.StdEncoding.EncodeToString(s)
		err := os.WriteFile(sharePaths[i], []byte(b64), 0600)
		if err != nil {
			return fmt.Errorf("failed to write share file '%s': %w", sharePaths[i], err)
		}
	}
	return nil
}

// ParseCommaSeparatedPaths is a helper to parse something like "foo.txt,bar.txt" into []string
func ParseCommaSeparatedPaths(input string) []string {
	if strings.TrimSpace(input) == "" {
		return nil
	}
	parts := strings.Split(input, ",")
	var out []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
