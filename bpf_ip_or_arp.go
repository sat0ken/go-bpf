package main

import (
	"fmt"
	"golang.org/x/net/bpf"
	"log"
	"main/utils"
	"syscall"
)

const (
	etOff  = 12
	etLen  = 2
	etARP  = 0x0806
	etIPv4 = 0x0800
)

// https://pkg.go.dev/golang.org/x/net/bpf#example-NewVM
func main() {

	instruction := []bpf.Instruction{
		// EthernetヘッダからTypeをロード
		bpf.LoadAbsolute{
			Off:  etOff,
			Size: etLen,
		},
		// TypeがARPならpaket受信にJump
		bpf.JumpIf{
			Cond:     bpf.JumpEqual,
			Val:      etARP,
			SkipTrue: 1,
		},
		// ARP以外のパケットは読み込まない
		bpf.RetConstant{Val: 0},
		// ARPパケットであれば1500byte読み込む
		bpf.RetConstant{Val: 1500},
	}

	for i := 0; i < len(instruction); i++ {
		fmt.Printf("%v\n", instruction[i])
	}

	vm, err := bpf.NewVM(instruction)

	if err != nil {
		panic(fmt.Sprintf("failed to load BPF program: %v", err))
	}

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

		out, err := vm.Run(buf)
		if err != nil {
			log.Fatalf("bpf run err : %v", err)
		}
		if out != 0 {
			fmt.Printf("recv arp is %x\n", buf[0:14])
		}
	}
}
