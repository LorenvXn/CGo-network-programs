package main

import (
    "fmt"
    "net"
    "syscall"
    "unsafe"
    "log"
)

/*
#include<stdlib.h>
#include<string.h>
#include<netinet/in.h>
#include<stdint.h>

typedef struct __attribute__((packed))
{

    char DestionationAddress[6];
    char SourceAddress[6];
    uint16_t Type;

} Ethernet_II_header;

typedef struct __attribute__((packed))
{

    uint16_t HardwareType;
    uint16_t ProtocolType;
    char HarwdwareAddressLength;
    char ProtocolAddressLength;
    uint16_t ARP_OperationCode;
    char SourceHardwareAddress[6];
    char SourceProtocolAddress[4];
    char TargetHardwareAddress[6];
    char TargetProtocolAddress[4];

} ARP_request_or_ARP_reply;

typedef struct __attribute__((packed))
{
    Ethernet_II_header eth; // 6+6+2 = 14
    ARP_request_or_ARP_reply arp; // 28
} ARPPacket; // 42 bits in total

char* ARPPacketFormat(char* SourceMacAddress, char* SourceAddressIp)
{

    ARPPacket * packet = malloc(sizeof(ARPPacket));
    memset(packet, 0, sizeof(ARPPacket));

    packet->eth.DestionationAddress[0] = 0xff;
    packet->eth.DestionationAddress[1] = 0xff;
    packet->eth.DestionationAddress[2] = 0xff;
    packet->eth.DestionationAddress[3] = 0xff;
    packet->eth.DestionationAddress[4] = 0xff;
    packet->eth.DestionationAddress[6] = 0xff;

    packet->eth.SourceAddress[0] = strtoul(SourceMacAddress, (void *)0, 16);  //base 16 ; atoi() won't detect errors
    SourceMacAddress += 3;
    packet->eth.SourceAddress[1] = strtoul(SourceMacAddress, (void *)0, 16); 
    SourceMacAddress += 3;
    packet->eth.SourceAddress[2] = strtoul(SourceMacAddress, (void *)0, 16); 
    SourceMacAddress += 3;
    packet->eth.SourceAddress[3] = strtoul(SourceMacAddress, (void *)0, 16); 
    SourceMacAddress += 3;
    packet->eth.SourceAddress[4] = strtoul(SourceMacAddress, (void *)0, 16); 
    SourceMacAddress += 3;
    packet->eth.SourceAddress[5] = strtoul(SourceMacAddress, (void *)0, 16);

    packet->eth.Type = htons(0x0806); // ARP type

    packet->arp.HardwareType = htons(0x0001); // Ethernet
    packet->arp.ProtocolType = htons(0x0800); //IP;
    packet->arp.HarwdwareAddressLength = 6; // Ethernet = 6
    packet->arp.ProtocolAddressLength = 4; //IPv4 = 4
    packet->arp.ARP_OperationCode = htons(0x0002); // response

    memcpy(packet->arp.SourceHardwareAddress, packet->eth.SourceAddress, 6);

    packet->arp.SourceProtocolAddress[0] = strtoul(SourceAddressIp, (void *)0, 10);  //base 10
    SourceAddressIp = index(SourceAddressIp, '.') + 1;
    packet->arp.SourceProtocolAddress[1] = strtoul(SourceAddressIp, (void *)0, 10); 
    SourceAddressIp = index(SourceAddressIp, '.') + 1;
    packet->arp.SourceProtocolAddress[2] = strtoul(SourceAddressIp, (void *)0, 10); 
    SourceAddressIp = index(SourceAddressIp, '.') + 1;
    packet->arp.SourceProtocolAddress[3] = strtoul(SourceAddressIp, (void *)0, 10);

    memcpy(packet->arp.TargetHardwareAddress, packet->arp.SourceHardwareAddress, 6);
    memcpy(packet->arp.TargetProtocolAddress, packet->arp.SourceProtocolAddress, 4);

    return (char*) packet;
}
*/
import "C"


func main() {

    newARP_packet := new(C.ARPPacket)
    ARP_packet_size := uint(unsafe.Sizeof(*newARP_packet))
    fmt.Println("Size of the newly created ARP packet: ", ARP_packet_size)


   file_descriptor, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, syscall.ETH_P_ALL)
    if err != nil {
        fmt.Println("Error: " + err.Error())
        return
    }
    fmt.Println("Value of File Descriptor [... if negative, is no use... ]:", file_descriptor)

	
    Iface, err := net.InterfaceByName("enp0s3")
  	if err != nil { 
		fmt.Println("Error: " + err.Error())
		return 
		}

    fmt.Println("Hardware Address: ", Iface.HardwareAddr)

    Iface_String := C.CString(Iface.HardwareAddr.String())
    IP_String := C.CString("10.0.2.15")

    packet := C.GoBytes(unsafe.Pointer(C.ARPPacketFormat(Iface_String, IP_String)) , C.int(ARP_packet_size))

    var address syscall.SockaddrLinklayerlType = htons(0x0800); //IP;
    address.Protocol = syscall.ETH_P_ARP
    address.Ifindex = Iface.Index
    address.Hatype = syscall.ARPHRD_ETHER

    err = syscall.Sendto(file_descriptor, packet, 0, &address)

    if err != nil {
        panic(err)
    } 
	log.Print("packet has been sent! \n")

}

// Eth Type 0x8060 not recognizable - 0x0806 works like a charm: 
// https://ftp.netbsd.org/pub/NetBSD/NetBSD-current/src/sys/net/ethertypes.h
// (output from tcpdump below)
//14:41:07.824615 IP 10.80.130.254.domain > 10.0.2.15.33394: 40515 NXDomain 0/1/0 (121)
//14:41:08.907918 08:00:27:e4:a6:ff (oui Unknown) > ff:ff:ff:ff:ff:00 (oui Unknown), ethertype Unknown (0x8060), length 42: 
//	0x0000:  0001 0800 0604 0002 0800 27e4 a6ff 0a00  ..........'.....
//	0x0010:  020f 0800 27e4 a6ff 0a00 020f            ....'.......
