package model

import "fmt"

type Request struct {
    Cmd       string    `json:"cmd"`
    Cleanup   bool      `json:"cleanup"`
    Address   string    `json:"address"`
    Container Container `json:"container"`
}

func (r Request) String() string {
    return fmt.Sprintf("Request[Cmd: %s, Cleanup: %t, Address %s, Container: %s]", r.Cmd, r.Cleanup, r.Address, r.Container)
}
