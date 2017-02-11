package cautils

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"time"
)

type CertificateRequest struct {
	DerBytes []byte

	Csr *x509.CertificateRequest
}

func NewCertificateRequest(key *Key, pubIp *string) (*CertificateRequest, error) {
	local, _, _ := net.ParseCIDR("127.0.0.1/24")

	nodeIps := []net.IP{local}
	addrs, err := net.InterfaceAddrs()
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				nodeIps = append(nodeIps, ipnet.IP)
			}
		}
	}
	if pubIp != nil && len(*pubIp) != 0 {
		public, _, _ := net.ParseCIDR(*pubIp + "/24")
		nodeIps = append(nodeIps, public)
	}

	template := &x509.CertificateRequest{
		Subject:     GenSubject("Hortonworks", "server.dc1.consul"),
		DNSNames:    []string{"localhost", "server.dc1.consul"},
		IPAddresses: nodeIps,
	}

	derBytes, err := x509.CreateCertificateRequest(rand.Reader, template, key.PrivateKey)
	if err != nil {
		return nil, err
	}
	csr, err := NewCertificateRequestFromDER(derBytes)
	if err != nil {
		return nil, err
	}

	return csr, nil
}

func SignCsr(ca *CA, csr *CertificateRequest) (*Certificate, error) {
	serialNumber, err := ca.GetSerialNumber()
	if err != nil {
		return nil, err
	}
	notBefore := time.Now()
	notAfter := notBefore.Add(time.Hour * 365 * 24)
	keyUsage := x509.KeyUsageDataEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement
	extKeyUsage := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               csr.Csr.Subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              keyUsage,
		ExtKeyUsage:           extKeyUsage,
		BasicConstraintsValid: true,
		DNSNames:              csr.Csr.DNSNames,
		IPAddresses:           csr.Csr.IPAddresses,
	}
	return CreateCertificate(template, ca.Certificate.Crt, csr.Csr.PublicKey, ca.Key.PrivateKey)
}

func certificateRequestFactoryByDER(derBytes []byte) (CertificateRequest, error) {
	csr, err := x509.ParseCertificateRequest(derBytes)
	if err != nil {
		return CertificateRequest{}, err
	}

	certificateRequest := CertificateRequest{
		DerBytes: derBytes,
		Csr:      csr,
	}

	return certificateRequest, nil
}

func certificateRequestFactoryByPEM(pemBytes []byte) (interface{}, error) {
	pemBlock, _ := pem.Decode(pemBytes)
	if pemBlock == nil {
		return nil, errors.New("PEM decode failed")
	}

	csr, err := certificateRequestFactoryByDER(pemBlock.Bytes)
	return csr, err
}

func NewCertificateRequestFromDER(derBytes []byte) (*CertificateRequest, error) {
	csr, err := certificateRequestFactoryByDER(derBytes)
	return &csr, err
}

func NewCertificateRequestFromPEM(pemBytes []byte) (*CertificateRequest, error) {
	rawCsr, err := certificateRequestFactoryByPEM(pemBytes)
	csr := rawCsr.(CertificateRequest)
	return &csr, err
}

func NewCertificateRequestFromPEMFile(filename string) (*CertificateRequest, error) {
	rawCsr, err := newFromPEMFile(filename, certificateRequestFactoryByPEM)
	csr := rawCsr.(CertificateRequest)
	return &csr, err
}

func (csr *CertificateRequest) ToPEM() ([]byte, error) {
	return toPemImpl("CERTIFICATE REQUEST", csr.DerBytes)
}

func (csr *CertificateRequest) ToPEMFile(filename string) error {
	return toPemFileImpl(csr, filename)
}
