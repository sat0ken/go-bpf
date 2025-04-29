package main

import (
	"fmt"
	"github.com/elastic/go-seccomp-bpf"
	"log"
	"syscall"
)

func main() {
	// Create a filter.
	filter := seccomp.Filter{
		NoNewPrivs: true,
		Flag:       seccomp.FilterFlagTSync,
		Policy: seccomp.Policy{
			DefaultAction: seccomp.ActionAllow,
			Syscalls: []seccomp.SyscallGroup{
				{
					Action: seccomp.ActionUserNotify,
					Names: []string{
						"getpid",
					},
				},
			},
		},
	}

	inst, err := filter.Policy.Assemble()
	if err != nil {
		log.Fatal("assemble failed:", err)
	}

	for i := 0; i < len(inst); i++ {
		fmt.Printf("%v\n", inst[i])
		raw, _ := inst[i].Assemble()
		fmt.Printf("%v %v, %v, %v\n", raw.Op, raw.Jt, raw.Jf, raw.K)
	}
	fmt.Printf("before load filter : %d\n", syscall.Getpid())
	// Load it. This will set no_new_privs before loading.
	if err := seccomp.LoadFilter(filter); err != nil {
		fmt.Println("failed to load filter: ", err)
		return
	}

	fmt.Printf("after load filter : %d\n", syscall.Getpid())
}
