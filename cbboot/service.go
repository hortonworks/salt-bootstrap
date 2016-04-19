package cbboot

import (
    "log"
    "github.com/sequenceiq/cloudbreak-bootstrap/cbboot/model"
    "net/http"
    "encoding/json"
)

func startSystemdService(w http.ResponseWriter, req *http.Request, service string) (out string, err error) {
    return startSrv(w, req, service, true)
}

func startService(w http.ResponseWriter, req *http.Request, service string) (out string, err error) {
    return startSrv(w, req, service, false)
}

func startSrv(w http.ResponseWriter, req *http.Request, service string, systemd bool) (out string, err error) {
    var result string
    if systemd {
        result, err = execCmd("/bin/systemctl", "start", service)
    } else {
        result, err = execCmd("/sbin/service", service, "start")
    }
    if err != nil {
        log.Printf("[startService] failed to start %s: %s", service, err.Error())
        w.WriteHeader(http.StatusInternalServerError)
        json.NewEncoder(w).Encode(model.Response{ErrorText: err.Error(), StatusCode:500})
    } else {
        status := http.StatusOK
        cResp := model.Response{Status:result, StatusCode:status}
        log.Printf("[startService] %s service started: %s", service, result)
        json.NewEncoder(w).Encode(cResp)
    }
    return result, err
}
