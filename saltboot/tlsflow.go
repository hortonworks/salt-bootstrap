package saltboot
import (
	"github.com/hortonworks/salt-bootstrap/saltboot/cautils"
  "fmt"
  "log"
  "net/http"
	"net/url"
  "os"
	"io/ioutil"
)


func PrivateKeyHandler(w http.ResponseWriter, req *http.Request) {
  // mkdir if needed
  log.Printf("[CAHandler] handlePrivateKey executed")
	w.Header().Set("Content-Type", "application/json")

  if cautils.IsPathExisting("./tlsauth") == false {
    if err := os.Mkdir("./tlsauth", 0755); err != nil {
      fmt.Fprintf(w, "FAIL")
      return
    }
  }
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
	fmt.Fprintf(w, "OK")
}

func CsrGenHandler(w http.ResponseWriter, req *http.Request) {
  log.Printf("[CAHandler] handleCsrGen executed")
	w.Header().Set("Content-Type", "application/json")
  if cautils.IsPathExisting("./tlsauth/client.key") == false {
    fmt.Fprintf(w, "FAIL")
    return
  }
  if cautils.IsPathExisting("./tlsauth/client.csr") == false {
    key, err  := cautils.NewKeyFromPrivateKeyPEMFile("./tlsauth/client.key")
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
  fmt.Fprintf(w, "OK")

}

func CsrSignHandler(w http.ResponseWriter, req * http.Request) {
	log.Printf("[CAHandler] handleCsrSign executed")
	w.Header().Set("Content-Type", "application/json")
	if cautils.IsPathExisting("./tlsauth/client.csr") == false {
    fmt.Fprintf(w, "FAIL")
    return
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
