package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"log"
	"my-pki/internal/utils"
	"strconv"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

// createSubjectFromInputs builds an x509 subject from form inputs
func createSubjectFromInputs(
	cn, org, ou, locality, province, country string,
) pkix.Name {
	// filter out empty values
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
	return subject
}

func showError(win fyne.Window, err error) {
	dialog.ShowError(err, win)
}

func createFileOpenButton(win fyne.Window, label string, targetEntry *widget.Entry) *widget.Button {
	return widget.NewButton(label, func() {
		dlg := dialog.NewFileOpen(
			func(reader fyne.URIReadCloser, err error) {
				if err != nil {
					showError(win, fmt.Errorf("error opening file: %w", err))
					return
				}
				if reader == nil {
					// user canceled
					return
				}
				path := reader.URI().Path()
				targetEntry.SetText(path)
				_ = reader.Close()
			},
			win,
		)
		dlg.SetFilter(nil)
		dlg.Show()
	})
}

func createFileSaveButton(win fyne.Window, label string, targetEntry *widget.Entry) *widget.Button {
	return widget.NewButton(label, func() {
		dlg := dialog.NewFileSave(
			func(writer fyne.URIWriteCloser, err error) {
				if err != nil {
					showError(win, fmt.Errorf("error saving file: %w", err))
					return
				}
				if writer == nil {
					// user canceled
					return
				}
				path := writer.URI().Path()
				targetEntry.SetText(path)
				_ = writer.Close()
			},
			win,
		)
		dlg.SetFilter(nil)
		dlg.Show()
	})
}

// -------------------------------------------------------------------------------------
// Root CA Tab
// -------------------------------------------------------------------------------------

func createRootTab(win fyne.Window) fyne.CanvasObject {
	// Subject Fields
	cnEntry := widget.NewEntry()
	cnEntry.SetPlaceHolder("e.g. My Root CA")

	orgEntry := widget.NewEntry()
	orgEntry.SetPlaceHolder("e.g. My Company")

	ouEntry := widget.NewEntry()
	ouEntry.SetPlaceHolder("e.g. Security Dept.")

	localityEntry := widget.NewEntry()
	localityEntry.SetPlaceHolder("City")

	provinceEntry := widget.NewEntry()
	provinceEntry.SetPlaceHolder("State/Province")

	countryEntry := widget.NewEntry()
	countryEntry.SetPlaceHolder("Country Code (e.g. US)")

	daysEntry := widget.NewEntry()
	daysEntry.SetText("365")

	// Shamir
	nEntry := widget.NewEntry()
	nEntry.SetText("3")
	nEntry.SetPlaceHolder("Number of shares")

	tEntry := widget.NewEntry()
	tEntry.SetText("2")
	tEntry.SetPlaceHolder("Threshold")

	// Output fields
	pemOutEntry := widget.NewEntry()
	pemOutEntry.SetPlaceHolder("Select output path for the Root CA PEM")

	sharesOutEntry := widget.NewEntry()
	sharesOutEntry.SetPlaceHolder("Auto-populated after using 'Add File'...")

	pemOutBrowse := createFileSaveButton(win, "Browse (PEM Out)", pemOutEntry)

	sharesOutBrowseBtn := widget.NewButton("Add Share File", func() {
		dlg := dialog.NewFileSave(
			func(writer fyne.URIWriteCloser, err error) {
				if err != nil {
					showError(win, err)
					return
				}
				if writer == nil {
					return
				}
				newPath := writer.URI().Path()
				_ = writer.Close()

				// Append to the existing text, comma-separated
				existing := sharesOutEntry.Text
				if existing == "" {
					sharesOutEntry.SetText(newPath)
				} else {
					sharesOutEntry.SetText(existing + "," + newPath)
				}
			},
			win,
		)
		dlg.Show()
	})

	// Create form sections
	subjectForm := &widget.Form{
		Items: []*widget.FormItem{
			{Text: "Common Name", Widget: cnEntry},
			{Text: "Organization", Widget: orgEntry},
			{Text: "Org Unit", Widget: ouEntry},
			{Text: "Locality", Widget: localityEntry},
			{Text: "Province", Widget: provinceEntry},
			{Text: "Country", Widget: countryEntry},
			{Text: "Days (Validity)", Widget: daysEntry},
		},
	}

	shamirForm := &widget.Form{
		Items: []*widget.FormItem{
			{Text: "Number of Shares (n)", Widget: nEntry},
			{Text: "Threshold (t)", Widget: tEntry},
		},
	}

	outputForm := &widget.Form{
		Items: []*widget.FormItem{
			{
				Text:   "Shares Out",
				Widget: container.NewBorder(nil, nil, nil, sharesOutBrowseBtn, sharesOutEntry),
			},
			{
				Text:   "PEM Out",
				Widget: container.NewBorder(nil, nil, nil, pemOutBrowse, pemOutEntry),
			},
		},
	}

	// Button to create
	createButton := widget.NewButtonWithIcon("Create Root CA", theme.ConfirmIcon(), func() {
		subject := createSubjectFromInputs(
			cnEntry.Text, orgEntry.Text, ouEntry.Text,
			localityEntry.Text, provinceEntry.Text, countryEntry.Text,
		)

		days, err := strconv.Atoi(daysEntry.Text)
		if err != nil {
			showError(win, fmt.Errorf("invalid days value: %w", err))
			return
		}

		n, err := strconv.Atoi(nEntry.Text)
		if err != nil {
			showError(win, fmt.Errorf("invalid n: %w", err))
			return
		}
		t, err := strconv.Atoi(tEntry.Text)
		if err != nil {
			showError(win, fmt.Errorf("invalid t: %w", err))
			return
		}

		if pemOutEntry.Text == "" {
			showError(win, fmt.Errorf("missing output path for root cert (PEM Out)"))
			return
		}

		sharePaths := strings.Split(strings.TrimSpace(sharesOutEntry.Text), ",")
		if len(sharePaths) != n {
			showError(win, fmt.Errorf("number of share paths must equal n=%d", n))
			return
		}

		// Generate
		ku := x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature
		certPEM, privKey, err := utils.GenerateKeyAndCert(subject, nil, nil, true, days, ku)
		if err != nil {
			showError(win, fmt.Errorf("failed to generate root CA: %w", err))
			return
		}

		// Write certificate
		err = utils.WriteCertificateToFile(certPEM, pemOutEntry.Text)
		if err != nil {
			showError(win, fmt.Errorf("failed to write root CA cert: %w", err))
			return
		}

		// Split the key with Shamir
		err = utils.SplitKeyAndWriteShares(privKey, n, t, sharePaths)
		if err != nil {
			showError(win, fmt.Errorf("failed to split key: %w", err))
			return
		}

		dialog.ShowInformation(
			"Success",
			fmt.Sprintf("Root CA created!\nCert: %s\n%d shares written.", pemOutEntry.Text, n),
			win,
		)
	})

	// Use cards or group containers
	subjectCard := widget.NewCard("Subject Information", "Fill out the certificate details", subjectForm)
	shamirCard := widget.NewCard("Shamir Parameters", "Threshold & shares for private key splitting", shamirForm)
	outputCard := widget.NewCard("Output Files", "Where to save the certificate and shares", outputForm)

	// Combine them into a single scrollable container
	content := container.NewVBox(
		subjectCard,
		shamirCard,
		outputCard,
		createButton,
	)
	return container.NewVScroll(content)
}

// -------------------------------------------------------------------------------------
// SubCA Tab
// -------------------------------------------------------------------------------------

func createSubCATab(win fyne.Window) fyne.CanvasObject {
	// Subject fields
	cnEntry := widget.NewEntry()
	cnEntry.SetPlaceHolder("e.g. My SubCA")

	orgEntry := widget.NewEntry()
	ouEntry := widget.NewEntry()
	localityEntry := widget.NewEntry()
	provinceEntry := widget.NewEntry()
	countryEntry := widget.NewEntry()

	daysEntry := widget.NewEntry()
	daysEntry.SetText("365")

	issuingCheck := widget.NewCheck("Issuing CA?", func(bool) {})

	parentPemEntry := widget.NewEntry()
	parentPemEntry.SetPlaceHolder("Select parent CA PEM file")
	parentPemBrowse := createFileOpenButton(win, "Browse (Parent PEM)", parentPemEntry)

	parentSharesEntry := widget.NewEntry()
	parentSharesEntry.SetPlaceHolder("Parent CA key share files (comma-separated)")

	addParentShareBtn := widget.NewButton("Add Parent Share", func() {
		dlg := dialog.NewFileOpen(
			func(reader fyne.URIReadCloser, err error) {
				if err != nil {
					showError(win, err)
					return
				}
				if reader == nil {
					return
				}
				newPath := reader.URI().Path()
				_ = reader.Close()

				existing := parentSharesEntry.Text
				if existing == "" {
					parentSharesEntry.SetText(newPath)
				} else {
					parentSharesEntry.SetText(existing + "," + newPath)
				}
			},
			win,
		)
		dlg.Show()
	})

	// Shamir
	nEntry := widget.NewEntry()
	nEntry.SetText("3")
	tEntry := widget.NewEntry()
	tEntry.SetText("2")

	sharesOutEntry := widget.NewEntry()
	sharesOutEntry.SetPlaceHolder("SubCA key shares will be saved here...")

	addSubShareBtn := widget.NewButton("Add Share Out (SubCA)", func() {
		dlg := dialog.NewFileSave(
			func(writer fyne.URIWriteCloser, err error) {
				if err != nil {
					showError(win, err)
					return
				}
				if writer == nil {
					return
				}
				newPath := writer.URI().Path()
				_ = writer.Close()

				existing := sharesOutEntry.Text
				if existing == "" {
					sharesOutEntry.SetText(newPath)
				} else {
					sharesOutEntry.SetText(existing + "," + newPath)
				}
			},
			win,
		)
		dlg.Show()
	})

	pemOutEntry := widget.NewEntry()
	pemOutEntry.SetPlaceHolder("Where to save the SubCA PEM certificate")
	pemOutBrowse := createFileSaveButton(win, "Browse (SubCA PEM Out)", pemOutEntry)

	// Sections
	subjectForm := &widget.Form{
		Items: []*widget.FormItem{
			{Text: "Common Name", Widget: cnEntry},
			{Text: "Organization", Widget: orgEntry},
			{Text: "Org Unit", Widget: ouEntry},
			{Text: "Locality", Widget: localityEntry},
			{Text: "Province", Widget: provinceEntry},
			{Text: "Country", Widget: countryEntry},
			{Text: "Days (Validity)", Widget: daysEntry},
		},
	}

	parentForm := &widget.Form{
		Items: []*widget.FormItem{
			{
				Text:   "Parent CA PEM",
				Widget: container.NewBorder(nil, nil, nil, parentPemBrowse, parentPemEntry),
			},
			{
				Text:   "Parent Shares",
				Widget: container.NewBorder(nil, nil, nil, addParentShareBtn, parentSharesEntry),
			},
		},
	}

	shamirForm := &widget.Form{
		Items: []*widget.FormItem{
			{Text: "Number of Shares (n)", Widget: nEntry},
			{Text: "Threshold (t)", Widget: tEntry},
			{
				Text:   "SubCA Shares Out",
				Widget: container.NewBorder(nil, nil, nil, addSubShareBtn, sharesOutEntry),
			},
		},
	}

	outputForm := &widget.Form{
		Items: []*widget.FormItem{
			{
				Text:   "SubCA PEM Out",
				Widget: container.NewBorder(nil, nil, nil, pemOutBrowse, pemOutEntry),
			},
		},
	}

	createButton := widget.NewButtonWithIcon("Create SubCA", theme.ConfirmIcon(), func() {
		subject := createSubjectFromInputs(
			cnEntry.Text, orgEntry.Text, ouEntry.Text,
			localityEntry.Text, provinceEntry.Text, countryEntry.Text,
		)

		days, err := strconv.Atoi(daysEntry.Text)
		if err != nil {
			showError(win, fmt.Errorf("invalid days: %w", err))
			return
		}
		if parentPemEntry.Text == "" {
			showError(win, fmt.Errorf("must specify parent-pem"))
			return
		}

		// Parse parent CA cert
		parentCert, err := utils.ParseCertificateFromFile(parentPemEntry.Text)
		if err != nil {
			showError(win, fmt.Errorf("failed to parse parent cert: %w", err))
			return
		}

		// Combine parent shares
		parentSharePaths := strings.Split(strings.TrimSpace(parentSharesEntry.Text), ",")
		if len(parentSharePaths) == 0 {
			showError(win, fmt.Errorf("no parent shares selected"))
			return
		}
		parentKeyBytes, err := utils.CombineSharesFromFiles(parentSharePaths)
		if err != nil {
			showError(win, fmt.Errorf("failed to combine parent shares: %w", err))
			return
		}
		parentKey, err := x509.ParseECPrivateKey(parentKeyBytes)
		if err != nil {
			showError(win, fmt.Errorf("failed to parse parent key: %w", err))
			return
		}

		// Generate SubCA
		ku := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		subCertPEM, subKey, err := utils.GenerateKeyAndCert(subject, parentCert, parentKey, true, days, ku)
		if err != nil {
			showError(win, fmt.Errorf("failed to generate subCA: %w", err))
			return
		}

		if pemOutEntry.Text == "" {
			showError(win, fmt.Errorf("must specify output path for subCA cert"))
			return
		}
		err = utils.WriteCertificateToFile(subCertPEM, pemOutEntry.Text)
		if err != nil {
			showError(win, fmt.Errorf("failed to write subCA cert: %w", err))
			return
		}

		// Shamir split
		n, err := strconv.Atoi(nEntry.Text)
		if err != nil {
			showError(win, fmt.Errorf("invalid n: %w", err))
			return
		}
		t, err := strconv.Atoi(tEntry.Text)
		if err != nil {
			showError(win, fmt.Errorf("invalid t: %w", err))
			return
		}
		subSharePaths := strings.Split(strings.TrimSpace(sharesOutEntry.Text), ",")
		if len(subSharePaths) != n {
			showError(win, fmt.Errorf("number of share files must match n=%d", n))
			return
		}
		err = utils.SplitKeyAndWriteShares(subKey, n, t, subSharePaths)
		if err != nil {
			showError(win, fmt.Errorf("failed to split subCA key: %w", err))
			return
		}

		dialog.ShowInformation(
			"Success",
			fmt.Sprintf("SubCA created!\nCert: %s\nIssuing: %v\n%d shares written.",
				pemOutEntry.Text,
				issuingCheck.Checked,
				n),
			win,
		)
	})

	subjectCard := widget.NewCard("Subject Information", "SubCA certificate details", subjectForm)
	parentCard := widget.NewCard("Parent CA", "Existing CA certificate and shares", parentForm)
	shamirCard := widget.NewCard("Shamir Parameters", "", shamirForm)
	outputCard := widget.NewCard("Output", "Where to save the new SubCA PEM", outputForm)

	content := container.NewVBox(
		subjectCard,
		issuingCheck,
		parentCard,
		shamirCard,
		outputCard,
		createButton,
	)
	return container.NewVScroll(content)
}

// -------------------------------------------------------------------------------------
// Sign Leaf Tab
// -------------------------------------------------------------------------------------

func signTab(win fyne.Window) fyne.CanvasObject {
	// Subject fields
	cnEntry := widget.NewEntry()
	cnEntry.SetPlaceHolder("Leaf certificate CN (e.g. myserver.local)")

	orgEntry := widget.NewEntry()
	ouEntry := widget.NewEntry()
	localityEntry := widget.NewEntry()
	provinceEntry := widget.NewEntry()
	countryEntry := widget.NewEntry()

	daysEntry := widget.NewEntry()
	daysEntry.SetText("365")

	caPemEntry := widget.NewEntry()
	caPemEntry.SetPlaceHolder("Select the parent CA PEM")
	caPemBrowse := createFileOpenButton(win, "Browse (CA PEM)", caPemEntry)

	sharesInEntry := widget.NewEntry()
	sharesInEntry.SetPlaceHolder("Select parent CA key shares...")

	addShareBtn := widget.NewButton("Add CA Share", func() {
		dlg := dialog.NewFileOpen(
			func(reader fyne.URIReadCloser, err error) {
				if err != nil {
					showError(win, err)
					return
				}
				if reader == nil {
					return
				}
				newPath := reader.URI().Path()
				_ = reader.Close()

				existing := sharesInEntry.Text
				if existing == "" {
					sharesInEntry.SetText(newPath)
				} else {
					sharesInEntry.SetText(existing + "," + newPath)
				}
			},
			win,
		)
		dlg.Show()
	})

	certOutEntry := widget.NewEntry()
	certOutEntry.SetPlaceHolder("Where to save the new leaf certificate")

	certOutBrowse := createFileSaveButton(win, "Browse (Leaf Cert Out)", certOutEntry)

	keyOutEntry := widget.NewEntry()
	keyOutEntry.SetPlaceHolder("Where to save the private key (optional)")
	keyOutBrowse := createFileSaveButton(win, "Browse (Leaf Key Out)", keyOutEntry)

	// KeyUsage checkboxes
	dsCheck := widget.NewCheck("Digital Signature", nil)
	keCheck := widget.NewCheck("Key Encipherment", nil)
	deCheck := widget.NewCheck("Data Encipherment", nil)
	kaCheck := widget.NewCheck("Key Agreement", nil)
	crlCheck := widget.NewCheck("CRL Sign", nil)
	eoCheck := widget.NewCheck("Encipher Only", nil)
	doCheck := widget.NewCheck("Decipher Only", nil)

	signButton := widget.NewButtonWithIcon("Sign Leaf Certificate", theme.ConfirmIcon(), func() {
		subject := createSubjectFromInputs(
			cnEntry.Text,
			orgEntry.Text,
			ouEntry.Text,
			localityEntry.Text,
			provinceEntry.Text,
			countryEntry.Text,
		)

		days, err := strconv.Atoi(daysEntry.Text)
		if err != nil {
			showError(win, fmt.Errorf("invalid days: %w", err))
			return
		}
		if caPemEntry.Text == "" {
			showError(win, fmt.Errorf("missing CA PEM path"))
			return
		}
		caCert, err := utils.ParseCertificateFromFile(caPemEntry.Text)
		if err != nil {
			showError(win, fmt.Errorf("failed to parse CA cert: %w", err))
			return
		}

		sharePaths := strings.Split(strings.TrimSpace(sharesInEntry.Text), ",")
		if len(sharePaths) == 0 {
			showError(win, fmt.Errorf("no CA key shares selected"))
			return
		}
		caKeyBytes, err := utils.CombineSharesFromFiles(sharePaths)
		if err != nil {
			showError(win, fmt.Errorf("failed to combine CA shares: %w", err))
			return
		}
		caKey, err := x509.ParseECPrivateKey(caKeyBytes)
		if err != nil {
			showError(win, fmt.Errorf("failed to parse CA key: %w", err))
			return
		}

		// Build KeyUsage
		var ku x509.KeyUsage
		if dsCheck.Checked {
			ku |= x509.KeyUsageDigitalSignature
		}
		if keCheck.Checked {
			ku |= x509.KeyUsageKeyEncipherment
		}
		if deCheck.Checked {
			ku |= x509.KeyUsageDataEncipherment
		}
		if kaCheck.Checked {
			ku |= x509.KeyUsageKeyAgreement
		}
		if crlCheck.Checked {
			ku |= x509.KeyUsageCRLSign
		}
		if eoCheck.Checked {
			ku |= x509.KeyUsageEncipherOnly
		}
		if doCheck.Checked {
			ku |= x509.KeyUsageDecipherOnly
		}

		// Generate & sign leaf
		certPEM, leafKey, err := utils.GenerateKeyAndCert(subject, caCert, caKey, false, days, ku)
		if err != nil {
			showError(win, fmt.Errorf("failed to sign leaf: %w", err))
			return
		}

		if certOutEntry.Text == "" {
			showError(win, fmt.Errorf("missing leaf cert output path"))
			return
		}
		err = utils.WriteCertificateToFile(certPEM, certOutEntry.Text)
		if err != nil {
			showError(win, fmt.Errorf("failed to write leaf cert: %w", err))
			return
		}

		if keyOutEntry.Text != "" {
			err := utils.WriteECPrivateKeyToFile(leafKey, keyOutEntry.Text)
			if err != nil {
				showError(win, fmt.Errorf("failed to write leaf key: %w", err))
				return
			}
		}

		dialog.ShowInformation(
			"Success",
			fmt.Sprintf("Leaf cert written to: %s\nLeaf key written to: %s",
				certOutEntry.Text, keyOutEntry.Text),
			win,
		)
	})

	// Build forms
	subjectForm := &widget.Form{
		Items: []*widget.FormItem{
			{Text: "Common Name", Widget: cnEntry},
			{Text: "Organization", Widget: orgEntry},
			{Text: "Org Unit", Widget: ouEntry},
			{Text: "Locality", Widget: localityEntry},
			{Text: "Province", Widget: provinceEntry},
			{Text: "Country", Widget: countryEntry},
			{Text: "Days (Validity)", Widget: daysEntry},
		},
	}

	caForm := &widget.Form{
		Items: []*widget.FormItem{
			{
				Text:   "CA PEM",
				Widget: container.NewBorder(nil, nil, nil, caPemBrowse, caPemEntry),
			},
			{
				Text:   "CA Key Shares",
				Widget: container.NewBorder(nil, nil, nil, addShareBtn, sharesInEntry),
			},
		},
	}

	outForm := &widget.Form{
		Items: []*widget.FormItem{
			{
				Text:   "Leaf Cert Out",
				Widget: container.NewBorder(nil, nil, nil, certOutBrowse, certOutEntry),
			},
			{
				Text:   "Leaf Key Out",
				Widget: container.NewBorder(nil, nil, nil, keyOutBrowse, keyOutEntry),
			},
		},
	}

	usageCard := widget.NewCard("Key Usage", "Select the key usages to enable",
		container.NewVBox(dsCheck, keCheck, deCheck, kaCheck, crlCheck, eoCheck, doCheck),
	)

	content := container.NewVBox(
		widget.NewCard("Leaf Certificate Subject", "", subjectForm),
		widget.NewCard("Parent CA Information", "", caForm),
		usageCard,
		widget.NewCard("Output Files", "", outForm),
		signButton,
	)

	return container.NewVScroll(content)
}

// -------------------------------------------------------------------------------------
// Main
// -------------------------------------------------------------------------------------

func main() {
	// Disable or redirect logs
	log.SetOutput(io.Discard)

	// Create the Fyne app
	a := app.NewWithID("com.mkarten.gosec")

	// (Optional) Use a built-in or custom theme
	// a.Settings().SetTheme(theme.DarkTheme())

	w := a.NewWindow("GoSec PKI Tool")
	w.Resize(fyne.NewSize(720, 800))

	// Create tabs
	rootTab := container.NewTabItem("Create Root CA", createRootTab(w))
	subCATab := container.NewTabItem("Create SubCA", createSubCATab(w))
	signTabItem := container.NewTabItem("Sign Leaf", signTab(w))

	tabs := container.NewAppTabs(
		rootTab,
		subCATab,
		signTabItem,
	)
	tabs.SetTabLocation(container.TabLocationTop)

	w.SetContent(tabs)
	w.ShowAndRun()
}
