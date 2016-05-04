package cbboot


import (
    "log"
    "github.com/sequenceiq/cloudbreak-bootstrap/cbboot/model"
    "net/http"
)

func HealthCheckHandler(w http.ResponseWriter, req *http.Request) {
    log.Printf("[HealthCheckHandler] handleHealtchCheck executed")
    w.Header().Set("Content-Type", "application/json")
    model.Response{Status: "OK"}.WriteHttp(w)
}

