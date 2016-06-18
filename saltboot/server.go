package saltboot

import (
	"encoding/json"
	"fmt"
	"github.com/sequenceiq/salt-bootstrap/saltboot/model"
	"log"
	"net/http"
	"os"
)

type Server struct {
	Name    string `json:"name"`
	Address string `json:"address"`
}

type Servers struct {
	Servers []Server `json:"servers"`
	Path    string   `  json:"path"`
}

func (s *Servers) WriteToFile() (outStr string, err error) {
	log.Printf("[Servers.writeToFile] %s", s)

	file := s.Path

	if _, err := os.Stat(file); os.IsNotExist(err) {
		if _, err := os.Create(file); err != nil {
			return "Failed to create " + file, err
		}
	}

	f, err := os.OpenFile(file, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return "Failed to open " + file, err
	}

	var serverList string
	for _, server := range s.Servers {
		serverList += fmt.Sprintf("\n%s %s", server.Address, server.Name)
	}
	log.Printf("[Servers.writeToFile] constructed server list: %s", serverList)

	if _, err = f.WriteString(serverList); err != nil {
		return "Failed to write to " + file, err
	}

	f.Close()

	return "Server list successfully appended to " + file, err
}

func ServerRequestHandler(w http.ResponseWriter, req *http.Request) {
	log.Printf("[serverRequestHandler] execute server request")

	decoder := json.NewDecoder(req.Body)
	var servers Servers
	err := decoder.Decode(&servers)
	if err != nil {
		log.Printf("[serverRequestHandler] [ERROR] couldn't decode json: %s", err.Error())
		model.Response{Status: err.Error()}.WriteBadRequestHttp(w)
		return
	}

	outStr, err := servers.WriteToFile()
	if err != nil {
		log.Printf("[serverRequestHandler] failed to write server address to file: %s", err.Error())
		model.Response{Status: err.Error(), StatusCode: http.StatusInternalServerError}.WriteHttp(w)
	} else {
		cResp := model.Response{Status: outStr}.WriteHttp(w)
		log.Printf("[serverRequestHandler] server request executed: %s", cResp.String())
	}
}

func (r Server) String() string {
	return fmt.Sprintf("Server[Name: %s, Address: %s]", r.Name, r.Address)
}
