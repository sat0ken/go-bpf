package main

import (
	"fmt"
	"github.com/elastic/go-seccomp-bpf"
	"log"
)

func main() {
	// Create a filter.
	filter := seccomp.Filter{
		NoNewPrivs: true,
		Flag:       seccomp.FilterFlagTSync,
		Policy: seccomp.Policy{
			DefaultAction: seccomp.ActionKillProcess,
			Syscalls: []seccomp.SyscallGroup{
				{
					Action: seccomp.ActionAllow,
					Names: []string{
						// "personality",
						"write",
						"mkdir",
						"getcwd",
					},
					NamesWithCondtions: []seccomp.NameWithConditions{
						{
							Name: "personality",
							Conditions: []seccomp.Condition{
								{
									Argument:  0,
									Operation: seccomp.Equal,
									Value:     8,
								},
							},
						},
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
		//fmt.Printf("%v\n", inst[i])
		raw, _ := inst[i].Assemble()
		fmt.Printf("code: %02x jt: %02x, jf: %02x, k: %08x\n", raw.Op, raw.Jt, raw.Jf, raw.K)
	}
	//fmt.Printf("before load filter : %d\n", syscall.Getpid())
	// Load it. This will set no_new_privs before loading.
	if err := seccomp.LoadFilter(filter); err != nil {
		log.Fatal("failed to load filter: ", err)
	}
	fmt.Println("Load seccomp filter is OK")

	//fmt.Printf("after load filter : %d\n", syscall.Getpid())
}
