package saltboot

import (
	"fmt"
	"github.com/hortonworks/salt-bootstrap/saltboot/cautils"
	"log"
	"net/http"
)

func CaHandler(w http.ResponseWriter, req *http.Request) {
	ca, err := cautils.NewCA("/etc/salt-bootstrap")
	if err != nil {
		panic(err)
	}
	pem, err := ca.Certificate.ToPEM()
	if err != nil {
		panic(err)
	}
	log.Printf("[CAHandler] handleCaCert executed")
	w.Header().Set("Content-Disposition", "attachment; filename=ca.crt")
	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	fmt.Fprintf(w, string(pem))
}

func CsrHandler(w http.ResponseWriter, req *http.Request) {
	csrString := req.FormValue("csr")
	csr, err := cautils.NewCertificateRequestFromPEM([]byte(csrString))
	if err != nil {
		panic(err)
	}

	newCA, err := cautils.NewCA("/etc/salt-bootstrap")
	if err != nil {
		panic(err)
	}
	cert, err := newCA.IssueCertificate(csr)
	if err != nil {
		panic(err)
	}

	certPem, err := cert.ToPEM()
	if err != nil {
		panic(err)
	}
	log.Printf("[CAHandler] handleCsr executed")
	w.Header().Set("Content-Disposition", "attachment; filename=client.crt")
	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	fmt.Fprintf(w, string(certPem))
}
