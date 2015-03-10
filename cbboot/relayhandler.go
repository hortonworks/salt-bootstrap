package cbboot

import (
    "log"

    "github.com/sequenceiq/cloudbreak-bootstrap/cbboot/model"


    "net/http"
    "fmt"
    "bytes"
    "encoding/json")



func relayConsulClusterRequest(consulClusterReq  model.ConsulClusterRequest) *model.RelayResponse {

    log.Println("[relayConsulClusterRequest] handleHealtchCheck executed: ", consulClusterReq)
    relayResp := new(model.RelayResponse)

    port := determineBootstrapPort()

    relayResp.Fill("", nil)

    for _, bs := range consulClusterReq.ConsulBootstraps {
        ipv4 := bs.Address

        url := fmt.Sprintf("http://%s:%d/cbboot/consul/launch", ipv4, port)

        msg := new(bytes.Buffer)
        err :=  json.NewEncoder(msg).Encode(consulClusterReq)
        log.Println("[relayConsulClusterRequest] message to relay: ", msg.String())
        if err != nil {
            relayResp.Fill("", err)
            return relayResp
        }

        resp, err := http.Post(url, "application/json", msg)

        cResp := new(model.Response)
        cResp.Address = ipv4
        if(err != nil) {
            cResp.Fill("", err)
        } else {
            err = json.NewDecoder(resp.Body).Decode(cResp)
            if(err != nil) {
                cResp.Fill("", err)
            }
        }

        relayResp.Responses = append(relayResp.Responses, *cResp)


    }

    return relayResp
}

