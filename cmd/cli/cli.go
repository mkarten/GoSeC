package main

import (
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/spf13/cobra"
	"my-pki/internal/utils"
	"os"
)

var rootCmd = &cobra.Command{
	Use:   "pki",
	Short: "A simple PKI CLI using Shamir Secret Sharing (no long-lived in-memory state)",
}

// create-root
var createRootCmd = &cobra.Command{
	Use:   "create-root",
	Short: "Create a new Root CA, split its private key, and output the PEM certificate + shares.",
	RunE: func(cmd *cobra.Command, args []string) error {
		subject, err := utils.BuildSubject(cmd)
		if err != nil {
			return err
		}

		days, _ := cmd.Flags().GetInt("days")
		n, _ := cmd.Flags().GetInt("n")
		t, _ := cmd.Flags().GetInt("t")
		pemOut, _ := cmd.Flags().GetString("pem-out")
		sharesOutStr, _ := cmd.Flags().GetString("shares-out")

		if pemOut == "" {
			return errors.New("must specify --pem-out for the root CA certificate")
		}
		if sharesOutStr == "" {
			return errors.New("must specify --shares-out for storing the key shares")
		}

		sharePaths := utils.ParseCommaSeparatedPaths(sharesOutStr)
		if len(sharePaths) == 0 {
			return errors.New("no valid file paths found in --shares-out")
		}
		if n != len(sharePaths) {
			return fmt.Errorf("number of share files (%d) does not match n=%d", len(sharePaths), n)
		}

		// Generate a self-signed root CA with default usage bits
		defaultRootKU := x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature
		certPEM, privKey, err := utils.GenerateKeyAndCert(subject, nil, nil, true, days, defaultRootKU)
		if err != nil {
			return fmt.Errorf("failed to generate root CA: %w", err)
		}

		// Write the certificate
		err = utils.WriteCertificateToFile(certPEM, pemOut)
		if err != nil {
			return fmt.Errorf("failed to write root CA cert to '%s': %w", pemOut, err)
		}

		// Split the root key
		err = utils.SplitKeyAndWriteShares(privKey, n, t, sharePaths)
		if err != nil {
			return fmt.Errorf("failed to split root key: %w", err)
		}

		fmt.Printf("Root CA created!\n - Certificate: %s\n - %d shares written.\n", pemOut, n)
		return nil
	},
}

// create-subca
var createSubCACmd = &cobra.Command{
	Use:   "create-subca",
	Short: "Create a new Sub-CA. Requires parent CA certificate + shares to sign. Splits subCA key similarly.",
	RunE: func(cmd *cobra.Command, args []string) error {
		subject, err := utils.BuildSubject(cmd)
		if err != nil {
			return err
		}
		days, _ := cmd.Flags().GetInt("days")
		isIssuing, _ := cmd.Flags().GetBool("issuing")

		parentPemPath, _ := cmd.Flags().GetString("parent-pem")
		if parentPemPath == "" {
			return errors.New("must specify --parent-pem for the parent CA certificate")
		}
		parentCert, err := utils.ParseCertificateFromFile(parentPemPath)
		if err != nil {
			return fmt.Errorf("failed to parse parent CA certificate: %w", err)
		}

		parentSharesInStr, _ := cmd.Flags().GetString("parent-shares-in")
		parentSharePaths := utils.ParseCommaSeparatedPaths(parentSharesInStr)
		if len(parentSharePaths) == 0 {
			return errors.New("no valid file paths found in --parent-shares-in")
		}
		parentKeyBytes, err := utils.CombineSharesFromFiles(parentSharePaths)
		if err != nil {
			return fmt.Errorf("failed to combine parent CA shares: %w", err)
		}
		parentKey, err := x509.ParseECPrivateKey(parentKeyBytes)
		if err != nil {
			return fmt.Errorf("failed to parse parent CA private key: %w", err)
		}

		// Default KeyUsage for subCA
		defaultSubCAKU := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		subCACertPEM, subCAKey, err := utils.GenerateKeyAndCert(subject, parentCert, parentKey, true, days, defaultSubCAKU)
		if err != nil {
			return fmt.Errorf("failed to generate subCA: %w", err)
		}

		subCAPemOut, _ := cmd.Flags().GetString("pem-out")
		if subCAPemOut == "" {
			return errors.New("must specify --pem-out to store the subCA certificate")
		}
		err = utils.WriteCertificateToFile(subCACertPEM, subCAPemOut)
		if err != nil {
			return fmt.Errorf("failed to write subCA certificate to '%s': %w", subCAPemOut, err)
		}

		n, _ := cmd.Flags().GetInt("n")
		t, _ := cmd.Flags().GetInt("t")
		sharesOutStr, _ := cmd.Flags().GetString("shares-out")
		sharePaths := utils.ParseCommaSeparatedPaths(sharesOutStr)
		if n != len(sharePaths) {
			return fmt.Errorf("number of share files (%d) does not match n=%d", len(sharePaths), n)
		}

		err = utils.SplitKeyAndWriteShares(subCAKey, n, t, sharePaths)
		if err != nil {
			return fmt.Errorf("failed to split subCA key: %w", err)
		}

		fmt.Printf("SubCA created!\n - Cert: %s\n - Issuing: %v\n - %d shares written.\n",
			subCAPemOut, isIssuing, n,
		)
		return nil
	},
}

// signCmd
var signCmd = &cobra.Command{
	Use:   "sign",
	Short: "Sign a leaf certificate with a given CA. Requires CA certificate and shares for private key.",
	RunE: func(cmd *cobra.Command, args []string) error {
		subject, err := utils.BuildSubject(cmd)
		if err != nil {
			return err
		}
		days, _ := cmd.Flags().GetInt("days")

		caPem, _ := cmd.Flags().GetString("ca-pem")
		if caPem == "" {
			return errors.New("must specify --ca-pem for the signing CA certificate")
		}
		caCert, err := utils.ParseCertificateFromFile(caPem)
		if err != nil {
			return fmt.Errorf("failed to parse CA certificate from '%s': %w", caPem, err)
		}

		sharesInStr, _ := cmd.Flags().GetString("shares-in")
		sharesInPaths := utils.ParseCommaSeparatedPaths(sharesInStr)
		if len(sharesInPaths) == 0 {
			return errors.New("no valid file paths in --shares-in")
		}

		caKeyBytes, err := utils.CombineSharesFromFiles(sharesInPaths)
		if err != nil {
			return fmt.Errorf("failed to combine CA shares: %w", err)
		}
		caKey, err := x509.ParseECPrivateKey(caKeyBytes)
		if err != nil {
			return fmt.Errorf("failed to parse CA private key: %w", err)
		}

		// Gather KeyUsage from boolean flags:
		var ku x509.KeyUsage
		digitalSig, _ := cmd.Flags().GetBool("digital-signature")
		keyEnc, _ := cmd.Flags().GetBool("key-encipherment")
		dataEnc, _ := cmd.Flags().GetBool("data-encipherment")
		keyAgree, _ := cmd.Flags().GetBool("key-agreement")
		crlSign, _ := cmd.Flags().GetBool("crl-sign")
		encipherOnly, _ := cmd.Flags().GetBool("encipher-only")
		decipherOnly, _ := cmd.Flags().GetBool("decipher-only")

		if digitalSig {
			ku |= x509.KeyUsageDigitalSignature
		}
		if keyEnc {
			ku |= x509.KeyUsageKeyEncipherment
		}
		if dataEnc {
			ku |= x509.KeyUsageDataEncipherment
		}
		if keyAgree {
			ku |= x509.KeyUsageKeyAgreement
		}
		if crlSign {
			ku |= x509.KeyUsageCRLSign
		}
		if encipherOnly {
			ku |= x509.KeyUsageEncipherOnly
		}
		if decipherOnly {
			ku |= x509.KeyUsageDecipherOnly
		}

		// Generate the leaf certificate + private key
		certPEM, leafPrivKey, err := utils.GenerateKeyAndCert(
			subject,
			caCert,
			caKey,
			false, // not a CA
			days,
			ku,
		)
		if err != nil {
			return fmt.Errorf("failed to sign leaf certificate: %w", err)
		}

		certOut, _ := cmd.Flags().GetString("cert-out")
		if certOut == "" {
			return errors.New("must specify --cert-out for the signed certificate")
		}
		err = utils.WriteCertificateToFile(certPEM, certOut)
		if err != nil {
			return fmt.Errorf("failed to write signed certificate to '%s': %w", certOut, err)
		}

		// If user specified --key-out, write the newly generated leaf key
		keyOut, _ := cmd.Flags().GetString("key-out")
		if keyOut != "" {
			err := utils.WriteECPrivateKeyToFile(leafPrivKey, keyOut)
			if err != nil {
				return fmt.Errorf("failed to write leaf private key to '%s': %w", keyOut, err)
			}
		}

		fmt.Printf("Signed certificate written to %s\n", certOut)
		if keyOut != "" {
			fmt.Printf("Leaf private key written to %s\n", keyOut)
		}
		return nil
	},
}

func main() {
	// Common subject flags
	addSubjectFlags := func(cmd *cobra.Command) {
		cmd.Flags().String("cn", "", "Common Name")
		cmd.Flags().String("org", "", "Organization Name")
		cmd.Flags().String("ou", "", "Organizational Unit")
		cmd.Flags().String("locality", "", "Locality (City)")
		cmd.Flags().String("province", "", "Province or State")
		cmd.Flags().String("country", "", "Country (2-letter code)")
		cmd.Flags().Int("days", 365, "Validity period (in days)")
	}

	// create-root
	addSubjectFlags(createRootCmd)
	createRootCmd.Flags().Int("n", 3, "Number of total key shares")
	createRootCmd.Flags().Int("t", 2, "Threshold (quorum) number of shares required to recover the key")
	createRootCmd.Flags().String("shares-out", "", "Comma-separated list of file paths for the key shares (must match n).")
	createRootCmd.Flags().String("pem-out", "", "File path for the output root CA certificate (PEM)")

	// create-subca
	addSubjectFlags(createSubCACmd)
	createSubCACmd.Flags().Bool("issuing", false, "Whether this subCA is an issuing CA or not (for informational use)")
	createSubCACmd.Flags().String("parent-pem", "", "File path to parent CA certificate (PEM)")
	createSubCACmd.Flags().String("parent-shares-in", "", "Comma-separated list of parent CA key share files")
	createSubCACmd.Flags().Int("n", 3, "Number of total key shares for subCA")
	createSubCACmd.Flags().Int("t", 2, "Threshold (quorum) number of shares for subCA")
	createSubCACmd.Flags().String("shares-out", "", "Comma-separated list of file paths for the subCA key shares (must match n).")
	createSubCACmd.Flags().String("pem-out", "", "File path for the output subCA certificate (PEM)")

	// sign
	addSubjectFlags(signCmd)
	signCmd.Flags().String("ca-pem", "", "File path to the signing CA certificate (PEM)")
	signCmd.Flags().String("shares-in", "", "Comma-separated list of share files for the signing CA's private key")
	signCmd.Flags().String("cert-out", "", "File path for the signed leaf certificate (PEM)")
	signCmd.Flags().String("key-out", "", "File path to store the newly generated leaf private key (PEM)")

	// KeyUsage flags (booleans)
	signCmd.Flags().Bool("digital-signature", false, "Enable x509.KeyUsageDigitalSignature")
	signCmd.Flags().Bool("key-encipherment", false, "Enable x509.KeyUsageKeyEncipherment")
	signCmd.Flags().Bool("data-encipherment", false, "Enable x509.KeyUsageDataEncipherment")
	signCmd.Flags().Bool("key-agreement", false, "Enable x509.KeyUsageKeyAgreement")
	signCmd.Flags().Bool("crl-sign", false, "Enable x509.KeyUsageCRLSign")
	signCmd.Flags().Bool("encipher-only", false, "Enable x509.KeyUsageEncipherOnly")
	signCmd.Flags().Bool("decipher-only", false, "Enable x509.KeyUsageDecipherOnly")

	// Register commands
	rootCmd.AddCommand(createRootCmd)
	rootCmd.AddCommand(createSubCACmd)
	rootCmd.AddCommand(signCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
