package main

import (
    "fmt"
    "net"
    "syscall"
)

/*
#include <stdint.h>
#include <stdlib.h>

 void ping()
{
        system("ping -c 2 localhost");
}

*/
import "C"


func main() {

    ps, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, syscall.ETH_P_ALL)
    if err != nil {
        fmt.Println("Error: " + err.Error())
        return
    }
    fmt.Println("Obtained fd ", ps)
    defer syscall.Close(ps)

    interf, err := net.InterfaceByName("eth0")
    if err != nil {
        fmt.Println("Could not find eth0 interface")
        return
    }
         fmt.Println("Interface hw address: ", interf.HardwareAddr)
         fmt.Println("MTU hw interface: ", interf.MTU)
         fmt.Println("Pinging...")
         C.ping()


}

