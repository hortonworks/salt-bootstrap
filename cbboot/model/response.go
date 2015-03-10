package model

import "fmt"
import "strings"

type Response struct {
	Status      string   `json:"status"`
	ErrorText   string   `json:"errorText,omitempty"`
	Address     string   `json:"address,omitempty"`
}


func (r *Response) Fill(outStr string, err error) {
	if err != nil {
		r.Status = "ERR"
		r.ErrorText =  strings.TrimSpace(outStr + " " + err.Error())
	} else {
		r.Status = "OK"
	}
}

func (r Response) String() string {
	return fmt.Sprintf("Response[Status: %s, ErrorText: %s]", r.Status, r.ErrorText)
}

