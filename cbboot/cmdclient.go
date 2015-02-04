package cbboot

import (
    "log"
    "errors"
    "os/exec"
    "strings")

func swramConstraints(host string, cmdArgs []string) {
    if(host != ""){
        cmdArgs = append(cmdArgs, "-e", "constraint:node=" + host)
    }
}

func cmdExecute(cmd string, host string, c Container) (outStr string, err error) {

    log.Println("[dockerExecute] Launch container with details: ",  c)
    var cmdArgs []string
    switch cmd {
        case "run": {
            cmdArgs = []string{cmd}
            cmdArgs = append(cmdArgs, "-d")
            swramConstraints(host, cmdArgs)
            for _, envVar := range c.EnvVars {
                cmdArgs = append(cmdArgs, "-e", envVar)
            }
            for _, vol := range c.Volumes {
                cmdArgs = append(cmdArgs, "-v", vol)
            }
            if(c.HostNet) {
                cmdArgs = append(cmdArgs, "--net=host")
            }
            if(c.AutoRestart) {
                cmdArgs = append(cmdArgs, "--restart=always")
            }
            if(c.Privileged) {
                cmdArgs = append(cmdArgs, "--privileged")
            }
            cmdArgs = append(cmdArgs, "--name", c.Name, c.Image)
        }
        case "rm": {
            cmdArgs = []string{cmd}
            swramConstraints(host, cmdArgs)
            cmdArgs = append(cmdArgs, "-f", c.Name)
        }
        default:
            return "", errors.New("docker command not supported: " + cmd)
    }
    log.Println("[dockerExecute] docker arguments: ",  cmdArgs)
    out, err := exec.Command("docker", cmdArgs...).CombinedOutput()

    outStr = strings.TrimSpace(string(out))

    if err != nil {
        log.Println("[dockerExecute] ERROR Failed to execute command:", cmdArgs)
        log.Println("[dockerExecute] ERROR Failure reason:", outStr)
    } else {
        log.Println("[dockerExecute] SUCCESS. Container Launched: ",  outStr)
    }

    return outStr, err
}