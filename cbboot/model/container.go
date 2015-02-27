package model

import "fmt"

type Container struct {
    Name         string   `json:"name"`
    Image        string   `json:"image"`
    Volumes      []string `json:"volumes"`
    EnvVars      []string `json:"envVars"`
    Options      string   `json:"options"`
    AutoRestart  bool     `json:"autoRestart"`
    Privileged   bool     `json:"privileged"`
    HostNet      bool     `json:"hostNet"`
}

func (c Container) String() string {
    return fmt.Sprintf("Container[Name: %s, Image: %s, Volumes: %s, EnvVars: %s, Options: %s, AutoRestart: %t, Privileged %t, HostNet %t]", c.Name, c.Image, c.Volumes, c.EnvVars, c.Options, c.AutoRestart, c.Privileged, c.HostNet)
}
