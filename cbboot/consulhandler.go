package cbboot

import (
    "log"

    "github.com/sequenceiq/cloudbreak-bootstrap/cbboot/model"
    "encoding/json"
    "bytes"
    "io/ioutil"
    "errors"
    "os"
    "path/filepath"
    "strings")



func executeConsulBootstrap(consulClusterReq  model.ConsulClusterRequest) *model.Response {

    log.Println("[executeConsulBootstrap] handleHealtchCheck executed: ", consulClusterReq)
    cResp := new(model.Response)

    advertiseAddress, consulJoin, err := determineConsulJoins(consulClusterReq)
    cResp.Address = advertiseAddress

    if err != nil {
        log.Println("[executeConsulBootstrap] ERROR determineConsulJoins:", err)
        cResp.Fill("", err)
        return cResp
    }

    err = writeConsulConfig(*consulJoin)

    if err != nil {
        cResp.Fill("", err)
        return cResp
    }

    cont := model.Container{Name: "consul", Image:  consulClusterReq.Image, AutoRestart: true, HostNet: true}
    var options string;
    if(advertiseAddress != "") {
        options = "-advertise " + advertiseAddress + " "
    }
    if(consulJoin.Server){
        options = options + "-server "
    }
    cont.Options = strings.TrimSpace(options)

    absPath, err := getConsulConfigLocation()
    if err != nil {
        cResp.Fill("", err)
        return cResp
    }
    cont.Volumes = []string{absPath + ":/config/join.json"}

    _, err = cmdExecute("rm", "", cont);
    if err != nil {
        log.Println("[executeConsulBootstrap] cleanup of container: ", err)
    }
    outStr, err := cmdExecute("run", "", cont);

    cResp.Fill(outStr, err)

    return cResp
}

func getConsulConfigLocation() (string, error) {
    var joinFile = os.Getenv("CBBOOT_JOIN_FILE")
    var err error;
    if joinFile == "" {
        os.MkdirAll("config", 0777)
        joinFile, err = filepath.Abs("config/join.json")
    }
    log.Println("[consulJoinFileLocation] joinFile location is: ", joinFile)
    return joinFile, err
}

func writeConsulConfig(consulJoin model.ConsulJoin) (error) {
    var b bytes.Buffer
    err :=  json.NewEncoder(&b).Encode(consulJoin)
    log.Println("[executeConsulBootstrap] encoded join.json: ", b.String())

    joinFile, err := getConsulConfigLocation()
    if err != nil {
        log.Println("[writeConsulConfig] ERROR Failed determine join.json location:", err)
        return err
    }
    err = ioutil.WriteFile(joinFile, b.Bytes(), 0644)
    if err != nil {
        log.Println("[writeConsulConfig] ERROR Failed to write join.json:", err)
    }
    return err
}

func determineConsulJoins(consulClusterReq  model.ConsulClusterRequest) (string, *model.ConsulJoin, error) {

    addrs, err := determineAddresses()
    log.Println("[determineConsulJoins] retrieved addesses: ", addrs)

    var advertiseAddress string

    consulJoin := new(model.ConsulJoin)

    for _, bs := range consulClusterReq.ConsulBootstraps {
        ipv4 := bs.Address
        if (bs.Server) {
            if (addrs[ipv4]) {
                log.Println("[determineConsulJoins] filtered out from join: ", ipv4)
                // bootstrap expect shall be set up only for servers
                consulJoin.BootstrapExpect = consulClusterReq.ServerCount
            } else {
                consulJoin.RetryJoin = append(consulJoin.RetryJoin, ipv4)
            }
        }
        if (addrs[ipv4]) {
            log.Println("[determineConsulJoins] advertiseAddress is: ", ipv4)
            if(advertiseAddress == "" || advertiseAddress == ipv4) {
                advertiseAddress = ipv4
                consulJoin.Server = bs.Server
            } else {
                log.Println("[determineConsulJoins] advertiseAddress is: ", ipv4)
                return "", nil, errors.New("Ambiguous advertise addresses: " + advertiseAddress + " and " + ipv4)
            }
        }
    }

    return advertiseAddress, consulJoin, err
}


