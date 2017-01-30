package saltboot

import (
	"fmt"
	"github.com/hortonworks/salt-bootstrap/saltboot/cautils"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
)

func ClientCredsHandler(w http.ResponseWriter, req *http.Request) {
	// mkdir if needed
	log.Printf("[CAHandler] handleClientCreds executed")
	w.Header().Set("Content-Type", "application/json")

	if cautils.IsPathExisting("./tlsauth") == false {
		if err := os.Mkdir("./tlsauth", 0755); err != nil {
			fmt.Fprintf(w, "FAIL")
			return
		}
	}
	caResp, _ := http.Get("http://127.0.0.1:7070/saltboot/ca")
	caBytes, _ := ioutil.ReadAll(caResp.Body)
	caCrt, err := cautils.NewCertificateFromPEM(caBytes)
	if err != nil {
		fmt.Fprintf(w, "FAIL")
		panic(err)
	}
	err = caCrt.ToPEMFile("./tlsauth/ca.crt")
	if cautils.IsPathExisting("./tlsauth/client.key") == false {
		key, err := cautils.NewKey()
		if err != nil {
			fmt.Fprintf(w, "FAIL")
			panic(err)
		}

		err = key.ToPEMFile("./tlsauth/client.key")
		if err != nil {
			fmt.Fprintf(w, "FAIL")
			panic(err)
		}
	}
	if cautils.IsPathExisting("./tlsauth/client.csr") == false {
		key, err := cautils.NewKeyFromPrivateKeyPEMFile("./tlsauth/client.key")
		if err != nil {
			fmt.Fprintf(w, "FAIL")
			panic(err)
		}

		csr, err := cautils.NewCertificateRequest(key)
		if err != nil {
			fmt.Fprintf(w, "FAIL")
			panic(err)
		}
		err = csr.ToPEMFile("./tlsauth/client.csr")
		if err != nil {
			fmt.Fprintf(w, "FAIL")
			panic(err)
		}
	}
	csr, err := cautils.NewCertificateRequestFromPEMFile("./tlsauth/client.csr")
	if err != nil {
		fmt.Fprintf(w, "FAIL")
		panic(err)
	}
	pem, _ := csr.ToPEM()
	data := make(url.Values)
	data.Add("csr", string(pem))
	//resp, err := http.PostForm("http://" + host + "/certificates", data)
	resp, _ := http.PostForm("http://127.0.0.1:7070/saltboot/csr", data)
	crtBytes, _ := ioutil.ReadAll(resp.Body)
	crt, err := cautils.NewCertificateFromPEM(crtBytes)
	if err != nil {
		fmt.Fprintf(w, "FAIL")
		panic(err)
	}
	err = crt.ToPEMFile("./tlsauth/client.crt")
	fmt.Fprintf(w, "OK")
}