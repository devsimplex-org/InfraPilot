package ssl

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/http/webroot"
	"github.com/go-acme/lego/v4/registration"
	"go.uber.org/zap"
)

// CertManager handles SSL certificate operations with Let's Encrypt
type CertManager struct {
	CertDir     string // Base directory for certificates (e.g., /etc/letsencrypt)
	WebRoot     string // Webroot directory for ACME HTTP-01 challenge (e.g., /var/www/acme-challenge)
	Email       string // Email for Let's Encrypt account
	Staging     bool   // Use staging server for testing
	logger      *zap.Logger
	accountFile string

	// DNS-01 challenge state
	dnsChallenges     map[string]*DNSChallenge
	dnsChallengesMu   sync.RWMutex
	pendingDNSCleanup map[string]func() error
}

// DNSChallenge represents a pending DNS-01 challenge
type DNSChallenge struct {
	Domain     string    `json:"domain"`
	Token      string    `json:"token"`
	KeyAuth    string    `json:"key_auth"`
	TXTRecord  string    `json:"txt_record"`
	TXTName    string    `json:"txt_name"`
	CreatedAt  time.Time `json:"created_at"`
	Verified   bool      `json:"verified"`
}

// NewCertManager creates a new certificate manager
func NewCertManager(certDir, webRoot, email string, staging bool, logger *zap.Logger) *CertManager {
	return &CertManager{
		CertDir:           certDir,
		WebRoot:           webRoot,
		Email:             email,
		Staging:           staging,
		logger:            logger,
		accountFile:       filepath.Join(certDir, "account.json"),
		dnsChallenges:     make(map[string]*DNSChallenge),
		pendingDNSCleanup: make(map[string]func() error),
	}
}

// User implements the lego registration.User interface
type User struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *User) GetEmail() string                        { return u.Email }
func (u *User) GetRegistration() *registration.Resource { return u.Registration }
func (u *User) GetPrivateKey() crypto.PrivateKey        { return u.key }

// AccountData stores the account info on disk
type AccountData struct {
	Email        string                 `json:"email"`
	Registration *registration.Resource `json:"registration"`
	KeyPEM       string                 `json:"key_pem"`
}

// RequestCertificate requests a new SSL certificate for the domain
func (m *CertManager) RequestCertificate(domain string) error {
	m.logger.Info("Requesting SSL certificate",
		zap.String("domain", domain),
		zap.Bool("staging", m.Staging),
	)

	// Get or create user
	user, err := m.getOrCreateUser()
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}

	// Create lego config
	config := lego.NewConfig(user)
	if m.Staging {
		config.CADirURL = lego.LEDirectoryStaging
	} else {
		config.CADirURL = lego.LEDirectoryProduction
	}
	config.Certificate.KeyType = certcrypto.RSA2048

	// Create client
	client, err := lego.NewClient(config)
	if err != nil {
		return fmt.Errorf("failed to create ACME client: %w", err)
	}

	// Use HTTP-01 challenge with webroot
	// Nginx will serve the challenge files from the webroot directory
	if m.WebRoot != "" {
		// Ensure webroot directory exists
		if err := os.MkdirAll(m.WebRoot, 0755); err != nil {
			return fmt.Errorf("failed to create webroot directory: %w", err)
		}

		provider, err := webroot.NewHTTPProvider(m.WebRoot)
		if err != nil {
			return fmt.Errorf("failed to create webroot provider: %w", err)
		}
		err = client.Challenge.SetHTTP01Provider(provider)
		if err != nil {
			return fmt.Errorf("failed to set HTTP-01 provider: %w", err)
		}
	} else {
		// Fallback to standalone server (for backwards compatibility)
		err = client.Challenge.SetHTTP01Provider(http01.NewProviderServer("", "80"))
		if err != nil {
			return fmt.Errorf("failed to set HTTP-01 provider: %w", err)
		}
	}

	// Register if needed
	if user.Registration == nil {
		reg, err := client.Registration.Register(registration.RegisterOptions{
			TermsOfServiceAgreed: true,
		})
		if err != nil {
			return fmt.Errorf("failed to register: %w", err)
		}
		user.Registration = reg

		// Save account
		if err := m.saveAccount(user); err != nil {
			m.logger.Warn("Failed to save account", zap.Error(err))
		}
	}

	// Request certificate
	request := certificate.ObtainRequest{
		Domains: []string{domain},
		Bundle:  true,
	}

	certificates, err := client.Certificate.Obtain(request)
	if err != nil {
		return fmt.Errorf("failed to obtain certificate: %w", err)
	}

	// Save certificates
	if err := m.saveCertificate(domain, certificates); err != nil {
		return fmt.Errorf("failed to save certificate: %w", err)
	}

	m.logger.Info("SSL certificate obtained successfully",
		zap.String("domain", domain),
	)

	return nil
}

// RenewCertificate renews an existing certificate
func (m *CertManager) RenewCertificate(domain string) error {
	m.logger.Info("Renewing SSL certificate", zap.String("domain", domain))

	// Check if certificate exists
	certPath := m.getCertPath(domain)
	if _, err := os.Stat(filepath.Join(certPath, "fullchain.pem")); os.IsNotExist(err) {
		return fmt.Errorf("certificate does not exist for domain: %s", domain)
	}

	// For renewal, we just request a new certificate
	return m.RequestCertificate(domain)
}

// GetCertificateExpiry returns the expiry date of a certificate
func (m *CertManager) GetCertificateExpiry(domain string) (time.Time, error) {
	certPath := filepath.Join(m.getCertPath(domain), "fullchain.pem")

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to read certificate: %w", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return time.Time{}, fmt.Errorf("failed to decode PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert.NotAfter, nil
}

// NeedsRenewal checks if a certificate needs renewal (within 30 days of expiry)
func (m *CertManager) NeedsRenewal(domain string, daysBeforeExpiry int) (bool, error) {
	expiry, err := m.GetCertificateExpiry(domain)
	if err != nil {
		return false, err
	}

	renewalTime := expiry.AddDate(0, 0, -daysBeforeExpiry)
	return time.Now().After(renewalTime), nil
}

// CertificateExists checks if a certificate exists for a domain
func (m *CertManager) CertificateExists(domain string) bool {
	certPath := filepath.Join(m.getCertPath(domain), "fullchain.pem")
	_, err := os.Stat(certPath)
	return err == nil
}

// getCertPath returns the path for a domain's certificates
func (m *CertManager) getCertPath(domain string) string {
	return filepath.Join(m.CertDir, "live", domain)
}

// saveCertificate saves the certificate and key to disk
func (m *CertManager) saveCertificate(domain string, cert *certificate.Resource) error {
	certPath := m.getCertPath(domain)

	// Create directory
	if err := os.MkdirAll(certPath, 0700); err != nil {
		return fmt.Errorf("failed to create cert directory: %w", err)
	}

	// Save certificate chain
	fullchainPath := filepath.Join(certPath, "fullchain.pem")
	if err := os.WriteFile(fullchainPath, cert.Certificate, 0644); err != nil {
		return fmt.Errorf("failed to write certificate: %w", err)
	}

	// Save private key
	privkeyPath := filepath.Join(certPath, "privkey.pem")
	if err := os.WriteFile(privkeyPath, cert.PrivateKey, 0600); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	// Also save separate cert file (without chain)
	certOnlyPath := filepath.Join(certPath, "cert.pem")
	if err := os.WriteFile(certOnlyPath, cert.Certificate, 0644); err != nil {
		return fmt.Errorf("failed to write cert: %w", err)
	}

	m.logger.Info("Saved certificate",
		zap.String("domain", domain),
		zap.String("path", certPath),
	)

	return nil
}

// getOrCreateUser gets or creates the ACME user
func (m *CertManager) getOrCreateUser() (*User, error) {
	// Try to load existing account
	user, err := m.loadAccount()
	if err == nil {
		return user, nil
	}

	m.logger.Info("Creating new ACME account", zap.String("email", m.Email))

	// Generate new private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	return &User{
		Email: m.Email,
		key:   privateKey,
	}, nil
}

// loadAccount loads the ACME account from disk
func (m *CertManager) loadAccount() (*User, error) {
	data, err := os.ReadFile(m.accountFile)
	if err != nil {
		return nil, err
	}

	var account AccountData
	if err := json.Unmarshal(data, &account); err != nil {
		return nil, err
	}

	// Parse private key
	block, _ := pem.Decode([]byte(account.KeyPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode key PEM")
	}

	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return &User{
		Email:        account.Email,
		Registration: account.Registration,
		key:          key,
	}, nil
}

// saveAccount saves the ACME account to disk
func (m *CertManager) saveAccount(user *User) error {
	// Encode private key
	keyBytes, err := x509.MarshalECPrivateKey(user.key.(*ecdsa.PrivateKey))
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyBytes,
	})

	account := AccountData{
		Email:        user.Email,
		Registration: user.Registration,
		KeyPEM:       string(keyPEM),
	}

	data, err := json.MarshalIndent(account, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal account: %w", err)
	}

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(m.accountFile), 0700); err != nil {
		return fmt.Errorf("failed to create account directory: %w", err)
	}

	if err := os.WriteFile(m.accountFile, data, 0600); err != nil {
		return fmt.Errorf("failed to write account file: %w", err)
	}

	m.logger.Info("Saved ACME account", zap.String("email", user.Email))
	return nil
}

// CertificateInfo contains information about a certificate
type CertificateInfo struct {
	Domain    string    `json:"domain"`
	Exists    bool      `json:"exists"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
	DaysLeft  int       `json:"days_left,omitempty"`
	Issuer    string    `json:"issuer,omitempty"`
	IsStaging bool      `json:"is_staging,omitempty"`
}

// GetCertificateInfo retrieves information about a domain's certificate
func (m *CertManager) GetCertificateInfo(domain string) (*CertificateInfo, error) {
	info := &CertificateInfo{
		Domain: domain,
		Exists: false,
	}

	if !m.CertificateExists(domain) {
		return info, nil
	}

	info.Exists = true

	// Read certificate
	certPath := filepath.Join(m.getCertPath(domain), "fullchain.pem")
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return info, fmt.Errorf("failed to read certificate: %w", err)
	}

	// Parse certificate
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return info, fmt.Errorf("failed to decode certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return info, fmt.Errorf("failed to parse certificate: %w", err)
	}

	info.ExpiresAt = cert.NotAfter
	info.DaysLeft = int(time.Until(cert.NotAfter).Hours() / 24)
	info.Issuer = cert.Issuer.CommonName

	// Check if it's a staging certificate
	if cert.Issuer.Organization != nil && len(cert.Issuer.Organization) > 0 {
		for _, org := range cert.Issuer.Organization {
			if org == "(STAGING) Let's Encrypt" {
				info.IsStaging = true
				break
			}
		}
	}

	return info, nil
}

// manualDNSProvider implements the challenge.Provider interface for manual DNS-01 challenges
type manualDNSProvider struct {
	manager   *CertManager
	domain    string
	presented bool
}

func (p *manualDNSProvider) Present(domain, token, keyAuth string) error {
	// Calculate the TXT record value
	txtValue := dns01.GetChallengeInfo(domain, keyAuth).Value
	txtName := "_acme-challenge." + dns01.UnFqdn(domain)

	p.manager.logger.Info("DNS-01 challenge presented",
		zap.String("domain", domain),
		zap.String("txt_name", txtName),
		zap.String("txt_value", txtValue),
	)

	// Store the challenge info
	p.manager.dnsChallengesMu.Lock()
	p.manager.dnsChallenges[p.domain] = &DNSChallenge{
		Domain:    p.domain,
		Token:     token,
		KeyAuth:   keyAuth,
		TXTRecord: txtValue,
		TXTName:   txtName,
		CreatedAt: time.Now(),
		Verified:  false,
	}
	p.manager.dnsChallengesMu.Unlock()

	p.presented = true
	return nil
}

func (p *manualDNSProvider) CleanUp(domain, token, keyAuth string) error {
	p.manager.logger.Info("DNS-01 challenge cleanup",
		zap.String("domain", domain),
	)

	// Remove challenge from map
	p.manager.dnsChallengesMu.Lock()
	delete(p.manager.dnsChallenges, p.domain)
	p.manager.dnsChallengesMu.Unlock()

	return nil
}

// Ensure manualDNSProvider implements the interface
var _ challenge.Provider = (*manualDNSProvider)(nil)

// captureDNSProvider captures DNS challenge info and waits for user confirmation
type captureDNSProvider struct {
	manager     *CertManager
	domain      string
	challengeCh chan *DNSChallenge
	doneCh      chan struct{}
}

func (p *captureDNSProvider) Present(domain, token, keyAuth string) error {
	// Calculate the TXT record value
	txtValue := dns01.GetChallengeInfo(domain, keyAuth).Value
	txtName := "_acme-challenge." + dns01.UnFqdn(domain)

	p.manager.logger.Info("DNS-01 challenge captured",
		zap.String("domain", domain),
		zap.String("txt_name", txtName),
		zap.String("txt_value", txtValue),
	)

	// Create and store the challenge
	challenge := &DNSChallenge{
		Domain:    p.domain,
		Token:     token,
		KeyAuth:   keyAuth,
		TXTRecord: txtValue,
		TXTName:   txtName,
		CreatedAt: time.Now(),
		Verified:  false,
	}

	p.manager.dnsChallengesMu.Lock()
	p.manager.dnsChallenges[p.domain] = challenge
	p.manager.dnsChallengesMu.Unlock()

	// Send challenge info to the waiting caller (non-blocking)
	select {
	case p.challengeCh <- challenge:
	default:
	}

	// Now wait for DNS propagation or timeout
	// We poll for the TXT record to appear
	p.manager.logger.Info("Waiting for DNS TXT record propagation...",
		zap.String("txt_name", txtName),
		zap.String("expected_value", txtValue),
	)

	// Poll for up to 10 minutes (user needs time to add the record)
	deadline := time.Now().Add(10 * time.Minute)
	checkInterval := 10 * time.Second

	for time.Now().Before(deadline) {
		// Check if TXT record exists
		records, err := net.LookupTXT(txtName)
		if err == nil {
			for _, record := range records {
				if record == txtValue {
					p.manager.logger.Info("DNS TXT record verified",
						zap.String("txt_name", txtName),
					)
					return nil
				}
			}
		}

		p.manager.logger.Debug("TXT record not found yet, retrying...",
			zap.String("txt_name", txtName),
			zap.Strings("found", records),
		)

		select {
		case <-p.doneCh:
			return fmt.Errorf("challenge cancelled")
		case <-time.After(checkInterval):
			// Continue polling
		}
	}

	return fmt.Errorf("timeout waiting for DNS TXT record: %s", txtName)
}

func (p *captureDNSProvider) CleanUp(domain, token, keyAuth string) error {
	p.manager.logger.Info("DNS-01 challenge cleanup (manual - user should remove TXT record)",
		zap.String("domain", domain),
	)
	return nil
}

var _ challenge.Provider = (*captureDNSProvider)(nil)

// StartDNSChallenge initializes a DNS-01 challenge and returns the TXT record info
// This creates the ACME account and calculates what TXT record will be needed
func (m *CertManager) StartDNSChallenge(domain string) (*DNSChallenge, error) {
	m.logger.Info("Starting DNS-01 challenge",
		zap.String("domain", domain),
		zap.Bool("staging", m.Staging),
	)

	// Get or create user
	user, err := m.getOrCreateUser()
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Create lego config
	config := lego.NewConfig(user)
	if m.Staging {
		config.CADirURL = lego.LEDirectoryStaging
	} else {
		config.CADirURL = lego.LEDirectoryProduction
	}
	config.Certificate.KeyType = certcrypto.RSA2048

	// Create client
	client, err := lego.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create ACME client: %w", err)
	}

	// Register if needed
	if user.Registration == nil {
		reg, err := client.Registration.Register(registration.RegisterOptions{
			TermsOfServiceAgreed: true,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to register: %w", err)
		}
		user.Registration = reg

		// Save account
		if err := m.saveAccount(user); err != nil {
			m.logger.Warn("Failed to save account", zap.Error(err))
		}
	}

	// Calculate the TXT record name
	baseDomain := domain
	if strings.HasPrefix(domain, "*.") {
		baseDomain = strings.TrimPrefix(domain, "*.")
	}
	txtName := "_acme-challenge." + baseDomain

	// Create a placeholder challenge - the actual TXT value will be determined
	// during the certificate request, but we provide the name so user can prepare
	challenge := &DNSChallenge{
		Domain:    domain,
		TXTName:   txtName,
		TXTRecord: "[Will be provided when challenge starts]",
		CreatedAt: time.Now(),
		Verified:  false,
	}

	// Store it
	m.dnsChallengesMu.Lock()
	m.dnsChallenges[domain] = challenge
	m.dnsChallengesMu.Unlock()

	// To get the actual TXT value, we need to start the ACME process
	// We'll use a channel-based provider that captures the challenge info

	captureProvider := &captureDNSProvider{
		manager:     m,
		domain:      domain,
		challengeCh: make(chan *DNSChallenge, 1),
		doneCh:      make(chan struct{}),
	}

	err = client.Challenge.SetDNS01Provider(captureProvider,
		dns01.AddRecursiveNameservers([]string{"8.8.8.8:53", "1.1.1.1:53"}),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to set DNS-01 provider: %w", err)
	}

	// For wildcard certificates, include both the wildcard and base domain
	domains := []string{domain}
	if strings.HasPrefix(domain, "*.") {
		baseDomain := strings.TrimPrefix(domain, "*.")
		domains = []string{domain, baseDomain}
	}

	// Start the obtain process in a goroutine
	go func() {
		request := certificate.ObtainRequest{
			Domains: domains,
			Bundle:  true,
		}
		// This will call Present() which captures the challenge and then blocks
		_, obtainErr := client.Certificate.Obtain(request)
		if obtainErr != nil {
			m.logger.Debug("Certificate obtain completed",
				zap.String("domain", domain),
				zap.Error(obtainErr),
			)
		}
	}()

	// Wait for the challenge info to be captured
	select {
	case capturedChallenge := <-captureProvider.challengeCh:
		return capturedChallenge, nil
	case <-time.After(30 * time.Second):
		return nil, fmt.Errorf("timeout waiting for ACME challenge")
	}
}

// GetDNSChallenge returns the current DNS challenge for a domain
func (m *CertManager) GetDNSChallenge(domain string) (*DNSChallenge, error) {
	m.dnsChallengesMu.RLock()
	defer m.dnsChallengesMu.RUnlock()

	challenge, exists := m.dnsChallenges[domain]
	if !exists {
		return nil, fmt.Errorf("no pending DNS challenge for domain: %s", domain)
	}

	return challenge, nil
}

// RequestCertificateWithDNS requests a certificate using DNS-01 challenge
// The TXT record must already be in place before calling this
func (m *CertManager) RequestCertificateWithDNS(domain string) error {
	m.logger.Info("Requesting SSL certificate with DNS-01",
		zap.String("domain", domain),
		zap.Bool("staging", m.Staging),
	)

	// Get or create user
	user, err := m.getOrCreateUser()
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}

	// Create lego config
	config := lego.NewConfig(user)
	if m.Staging {
		config.CADirURL = lego.LEDirectoryStaging
	} else {
		config.CADirURL = lego.LEDirectoryProduction
	}
	config.Certificate.KeyType = certcrypto.RSA2048

	// Create client
	client, err := lego.NewClient(config)
	if err != nil {
		return fmt.Errorf("failed to create ACME client: %w", err)
	}

	// Create a provider that just returns success (TXT record should already be in place)
	dnsProvider := &presetDNSProvider{
		manager: m,
		domain:  domain,
	}

	err = client.Challenge.SetDNS01Provider(dnsProvider,
		dns01.AddRecursiveNameservers([]string{"8.8.8.8:53", "1.1.1.1:53"}),
		dns01.DisableCompletePropagationRequirement(),
	)
	if err != nil {
		return fmt.Errorf("failed to set DNS-01 provider: %w", err)
	}

	// Register if needed
	if user.Registration == nil {
		reg, err := client.Registration.Register(registration.RegisterOptions{
			TermsOfServiceAgreed: true,
		})
		if err != nil {
			return fmt.Errorf("failed to register: %w", err)
		}
		user.Registration = reg

		if err := m.saveAccount(user); err != nil {
			m.logger.Warn("Failed to save account", zap.Error(err))
		}
	}

	// For wildcard certificates, include both the wildcard and base domain
	domains := []string{domain}
	if strings.HasPrefix(domain, "*.") {
		// For wildcard, also include the base domain
		baseDomain := strings.TrimPrefix(domain, "*.")
		domains = []string{domain, baseDomain}
	}

	// Request certificate
	request := certificate.ObtainRequest{
		Domains: domains,
		Bundle:  true,
	}

	certificates, err := client.Certificate.Obtain(request)
	if err != nil {
		return fmt.Errorf("failed to obtain certificate: %w", err)
	}

	// Save certificates - use base domain for wildcard certs
	saveDomain := domain
	if strings.HasPrefix(domain, "*.") {
		saveDomain = strings.TrimPrefix(domain, "*.")
	}

	if err := m.saveCertificate(saveDomain, certificates); err != nil {
		return fmt.Errorf("failed to save certificate: %w", err)
	}

	// Clean up challenge state
	m.dnsChallengesMu.Lock()
	delete(m.dnsChallenges, domain)
	m.dnsChallengesMu.Unlock()

	m.logger.Info("SSL certificate obtained successfully with DNS-01",
		zap.String("domain", domain),
		zap.Strings("domains", domains),
	)

	return nil
}

// presetDNSProvider is a DNS provider for when TXT records are already in place
type presetDNSProvider struct {
	manager *CertManager
	domain  string
}

func (p *presetDNSProvider) Present(domain, token, keyAuth string) error {
	// TXT record should already be in place - just log
	txtValue := dns01.GetChallengeInfo(domain, keyAuth).Value
	txtName := "_acme-challenge." + dns01.UnFqdn(domain)

	p.manager.logger.Info("DNS-01 using preset TXT record",
		zap.String("domain", domain),
		zap.String("txt_name", txtName),
		zap.String("txt_value", txtValue),
	)
	return nil
}

func (p *presetDNSProvider) CleanUp(domain, token, keyAuth string) error {
	p.manager.logger.Info("DNS-01 cleanup (manual - user should remove TXT record)",
		zap.String("domain", domain),
	)
	return nil
}

var _ challenge.Provider = (*presetDNSProvider)(nil)
