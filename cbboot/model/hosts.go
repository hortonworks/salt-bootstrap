package model

import (
	"fmt"
)

type Clients struct {
	Clients []string   `json:"clients,omitempty"`
	Server  string	   `json:"server"`
}

func (r Clients) String() string {
	return fmt.Sprintf("Host[Clients: %s, Server: %s]", r.Clients, r.Server)
}
