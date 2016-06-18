package saltboot

import (
	"github.com/sequenceiq/salt-bootstrap/saltboot/model"
	"log"
	"net/http"
)

func HealthCheckHandler(w http.ResponseWriter, req *http.Request) {
	log.Printf("[HealthCheckHandler] handleHealtchCheck executed")
	w.Header().Set("Content-Type", "application/json")
	model.Response{Status: "OK", Version: Version + "-" + BuildTime}.WriteHttp(w)
}
