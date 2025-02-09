# GoSeC

A simple PKI application built in **Go** that uses [**Shamir’s Secret Sharing**](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing) (via [HashiCorp Vault’s library](https://github.com/hashicorp/vault/tree/main/shamir)) to split and re-combine private keys. The project includes:

1. A **CLI** tool (`gosec-cli`), built with [Cobra](https://github.com/spf13/cobra).  
2. A **GUI** application (`gosec-gui`), which wraps the CLI functionality in a graphical interface.

Both tools are located under their respective directories:
- **CLI** in `cmd/cli`
- **GUI** in `cmd/gui`

---

## Features

- **Create a Root CA**:
  - Self-signs a certificate for the root CA.
  - Splits the **root private key** into `N` shares with a threshold `T`.
  - Writes the resulting **root certificate** to a PEM file, and each share to separate files.
- **Create a Sub-CA**:
  - Uses an **existing CA certificate + shares** to re-combine the parent’s private key.
  - Issues (signs) a **sub-CA** certificate.
  - Splits the **sub-CA’s private key** into new shares, writes them to files, and saves the sub-CA certificate to a PEM file.
- **Sign a Leaf Certificate**:
  - Re-combines a CA private key from shares (either root or sub-CA).
  - Signs a **leaf certificate** (with user-provided KeyUsage flags).
  - Optionally exports the newly generated leaf private key to a file.

---

## Installation & Releases

### 1. Download from GitHub Releases

Prebuilt binaries are provided for both **CLI** (`gosec-cli`) and **GUI** (`gosec-gui`) on the [GitHub Releases](https://github.com/mkarten/GoSeC.git) page. Download the appropriate one for your operating system:

- `gosec-cli` – for command-line usage.
- `gosec-gui` – for the graphical interface.

After downloading, place them in a directory on your `PATH` or anywhere convenient. Then:

- **CLI**: Run `gosec-cli --help`
- **GUI**: Double-click (on supported OS) or launch via the terminal: `./gosec-gui`

### 2. Build from Source

1. **Clone** this repository and install dependencies:

   ```bash
   git clone https://github.com/mkarten/GoSeC.git
   cd GoSeC
   go mod tidy
   ```

2. **Build the CLI**:

   ```bash
   go build -o gosec-cli ./cmd/cli
   ```

3. **Build the GUI**:

   ```bash
   go build -o gosec-gui ./cmd/gui
   ```

You will now have two executables:
- `gosec-cli` (the command-line interface)
- `gosec-gui` (the graphical interface)

---

## Usage: CLI (`gosec-cli`)

Below is an overview of the **CLI** commands.

### 1. `create-root`

Creates a **self-signed root CA**, splits its private key into shares, and writes the root certificate to disk.

**Flags** (select highlights):

- `--cn` (string): Common Name (required).
- `--org`, `--ou`, `--locality`, `--province`, `--country` (string): Optional subject fields.
- `--days` (int): Certificate validity in days (default `365`).
- `--n` (int): Number of key shares to generate.
- `--t` (int): Threshold of shares needed to reconstruct the key.
- `--pem-out` (string): Output path for the root CA certificate (PEM).
- `--shares-out` (string): Comma-separated file paths for each share (must match `--n`).

**Example**:

```bash
./gosec-cli create-root \
  --cn "MyRootCA" \
  --org "MyOrganization" \
  --days 3650 \
  --n 3 \
  --t 2 \
  --pem-out rootCA.pem \
  --shares-out "root-share1.txt,root-share2.txt,root-share3.txt"
```

- This creates `rootCA.pem` and 3 share files (`root-share1.txt`, `root-share2.txt`, `root-share3.txt`).
- Any 2 of those shares will be enough to reconstruct the **root** private key.

---

### 2. `create-subca`

Creates a **subordinate CA** by using an existing parent CA’s certificate and key shares. It then splits the sub-CA’s key.

**Flags** (select highlights):

- `--cn` (string): Common Name (required).
- Other subject flags: `--org`, `--ou`, `--locality`, `--province`, `--country`.
- `--days` (int): Validity in days for the sub-CA.
- `--issuing` (bool): Marks this sub-CA as “issuing” or not (for informational purposes).
- `--parent-pem` (string): Path to the **parent CA certificate** (PEM).
- `--parent-shares-in` (string): Comma-separated paths to the **parent CA’s key shares**.
- `--n` / `--t`: Number and threshold for the **new** sub-CA’s shares.
- `--shares-out` (string): Output file paths for the **new** sub-CA shares.
- `--pem-out` (string): Output path for the sub-CA certificate (PEM).

**Example**:

```bash
./gosec-cli create-subca \
  --cn "IntermediateCA" \
  --org "MyOrg" \
  --days 730 \
  --issuing=true \
  --parent-pem rootCA.pem \
  --parent-shares-in "root-share1.txt,root-share2.txt" \
  --n 3 \
  --t 2 \
  --shares-out "subca-share1.txt,subca-share2.txt,subca-share3.txt" \
  --pem-out subCA.pem
```

- Here, 2 shares of the **root CA** (`root-share1.txt` + `root-share2.txt`) reconstruct the root key in memory.
- The newly created sub-CA’s certificate is `subCA.pem`.
- The sub-CA’s private key is split into 3 new shares (`subca-share1.txt`, etc.).

---

### 3. `sign`

Signs a **leaf certificate** (or any certificate) with an existing CA. Allows specifying KeyUsage bits, and optionally writes out the leaf private key.

**Flags** (select highlights):

- `--cn`, `--org`, `--ou`, `--locality`, `--province`, `--country`: Subject fields.
- `--days` (int): Validity period.
- `--ca-pem` (string): Path to the **CA’s certificate** (PEM).
- `--shares-in` (string): Comma-separated key share file paths for the CA private key.
- `--cert-out` (string): Output path for the signed certificate (PEM).
- `--key-out` (string): **Optional** output path for the newly generated leaf private key (PEM). If omitted, the key is not stored.
- **KeyUsage flags** (boolean):
    - `--digital-signature`
    - `--key-encipherment`
    - `--data-encipherment`
    - `--key-agreement`
    - `--crl-sign`
    - `--encipher-only`
    - `--decipher-only`

**Example**:

```bash
./gosec-cli sign \
  --ca-pem subCA.pem \
  --shares-in "subca-share1.txt,subca-share2.txt" \
  --cn "myserver.local" \
  --org "MyOrg" \
  --days 365 \
  --cert-out myserver.pem \
  --key-out myserver-key.pem \
  --digital-signature \
  --key-encipherment
```

- This re-combines the sub-CA key from 2 shares, creates a certificate valid for 365 days, and writes it to `myserver.pem`.
- The **leaf private key** is written to `myserver-key.pem`.
- Key Usage includes **Digital Signature** and **Key Encipherment**.

---

## Usage: GUI (`gosec-gui`)

The **GUI** is a graphical interface on top of the same PKI logic. Just launch the command, and the application starts:

```bash
./gosec-gui
```

Use the on-screen options to:
- Create or load CAs and shares.
- Sign new certificates.
- Save or load key material as needed.

---

## Example Workflow

1. **Create a Root CA** (CLI):

   ```bash
   ./gosec-cli create-root \
     --cn "RootCA" \
     --org "MyOrg" \
     --days 3650 \
     --n 3 \
     --t 2 \
     --pem-out rootCA.pem \
     --shares-out "root-share1.txt,root-share2.txt,root-share3.txt"
   ```

2. **Create a Sub-CA** (CLI):

   ```bash
   ./gosec-cli create-subca \
     --cn "IntermediateCA" \
     --org "MyOrg" \
     --days 730 \
     --issuing=true \
     --parent-pem rootCA.pem \
     --parent-shares-in "root-share1.txt,root-share2.txt" \
     --n 3 \
     --t 2 \
     --shares-out "subca-share1.txt,subca-share2.txt,subca-share3.txt" \
     --pem-out subCA.pem
   ```

3. **Sign a Leaf Certificate** (CLI or GUI):

    - **CLI** example:
      ```bash
      ./gosec-cli sign \
        --ca-pem subCA.pem \
        --shares-in "subca-share1.txt,subca-share2.txt" \
        --cn "myserver.local" \
        --org "MyOrg" \
        --days 365 \
        --cert-out myserver.pem \
        --key-out myserver-key.pem \
        --digital-signature \
        --key-encipherment
      ```
    - **GUI** example:
      ```bash
      # Just launch the GUI:
      ./gosec-gui
 
      # Then use the GUI to select subCA.pem, provide share files, 
      # fill certificate details, and click "Sign."
      ```

4. **Verify** (CLI side):

   ```bash
   openssl x509 -in myserver.pem -text -noout
   ```
    - You’ll see the issuer, subject, validity, and Key Usage fields.

---

## Security Considerations

1. **Key Exposure**: Private keys are only reconstructed in memory briefly. All key material otherwise exists as Shamir shares in separate files.  
2. **Share Protection**: Each share file should be stored securely. An attacker with a sufficient threshold of shares can fully reconstruct the private key.
3. **No Revocation Mechanism**: This demonstration does not support CRLs or OCSP. In production, you need a strategy for certificate revocation.
4. **Encryption**: The share files are unencrypted beyond base64 encoding. Store them securely or add an additional encryption layer if required.

---

## Development Notes

- Built in **Go** using [Cobra](https://github.com/spf13/cobra) for the **CLI** in `/cmd/cli` and [fyne](https://github.com/fyne-io/fyne) for the **GUI** in `/cmd/gui`.
- Shamir Secret Sharing is via [HashiCorp Vault’s library](https://github.com/hashicorp/vault/tree/main/shamir).
- Certificate creation uses standard Go libraries: `crypto/x509`, `crypto/ecdsa`, etc.
- The “subject” flags for the CLI include `--cn`, `--org`, `--ou`, `--locality`, `--province`, `--country`.
- Key Usage for the **sign** command can be controlled by multiple boolean flags.

---

## License & Disclaimer

- This sample code is provided **as-is** for demonstration purposes.
- In a real production environment, you should implement:
    - Secure storage for keys,
    - Proper certificate revocation (CRL/OCSP),
    - Logging, auditing, etc.
- Protect your Shamir share files according to your organization’s security policies.

first version of gui and cli for gosec 1.0.0