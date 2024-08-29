package main

import (
	"bytes"
	"fmt"
	"log"
	"main/utils"
	"syscall"
)

// https://mmi.hatenablog.com/entry/2016/08/01/031233
// パケットをキャプチャしてそれがIPパケットかARPパケットかそれ以外かを出力するだけのプログラム
func main() {

	ifr, err := utils.GetInterfaceIndex("wlp0s20f3")
	if err != nil {
		log.Fatalf("failed to get interface index: %v", err)
	}

	sock, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(syscall.ETH_P_ALL))
	if err != nil {
		log.Fatalf("create socket err : %s", err)
	}
	defer syscall.Close(sock)

	addr := syscall.SockaddrLinklayer{
		Protocol: utils.Htons(syscall.ETH_P_ALL),
		Ifindex:  ifr,
	}
	err = syscall.Bind(sock, &addr)
	if err != nil {
		log.Fatalf("bind err : %s", err)
	}

	for {
		buf := make([]byte, 1500)
		_, _, err := syscall.Recvfrom(sock, buf, 0)
		if err != nil {
			log.Fatalf("read err : %v", err)
		}

		if bytes.Equal(buf[12:14], []byte{0x08, 0x00}) {
			fmt.Println("recv ipv4 packet")
		} else if bytes.Equal(buf[12:14], []byte{0x08, 0x06}) {
			fmt.Println("recv ipv4 packet")
		}
	}
}
