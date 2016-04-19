package model

import "fmt"
import (
    "strings"
    "encoding/json"
)

type Response struct {
    Status     string   `json:"status,omitempty"`
    ErrorText  string   `json:"errorText,omitempty"`
    Address    string   `json:"address,omitempty"`
    StatusCode int      `json:"statusCode,omitempty"`
}

type Responses struct {
    Responses []Response   `json:"responses"`
}

func (r *Response) Fill(outStr string, err error) {
    if err != nil {
        r.Status = "ERR"
        r.ErrorText = strings.TrimSpace(outStr + " " + err.Error())
    } else {
        r.Status = "OK"
    }
}

func (r Responses) String() string {
    j, _ := json.Marshal(r)
    return fmt.Sprintf("Responses: %s", string(j))
}

func (r Response) String() string {
    j, _ := json.Marshal(r)
    return fmt.Sprintf("Response: %s", string(j))
}

