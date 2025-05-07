package main

import (
	"encoding/json"
	"fmt"
	"github.com/elastic/go-seccomp-bpf"
	"golang.org/x/net/bpf"
	"log"
	"os"
)

// Condition represents conditions for syscall rules (includes/excludes).
type Condition struct {
	MinKernel string   `json:"minKernel,omitempty"`
	Arches    []string `json:"arches,omitempty"`
	Caps      []string `json:"caps,omitempty"`
}

// SyscallArg represents arguments for syscall rules.
type SyscallArg struct {
	Index uint   `json:"index"`
	Value uint64 `json:"value"` // Use uint64 as the value can be large
	Op    string `json:"op"`
}

func (syscallArg SyscallArg) convertOp(opstr string) seccomp.Operation {
	var op seccomp.Operation
	switch opstr {
	case "SCMP_CMP_EQ":
		op = seccomp.Equal
	case "SCMP_CMP_NE":
		op = seccomp.NotEqual
	case "SCMP_CMP_MASKED_EQ":
		op = seccomp.BitsSet
	}
	return op
}

// Syscall represents a single syscall rule in the seccomp profile.
type Syscall struct {
	Names    []string     `json:"names"`
	Action   string       `json:"action"`
	ErrnoRet int          `json:"errnoRet,omitempty"` // Use omitempty as it's optional
	Args     []SyscallArg `json:"args,omitempty"`     // Use omitempty as it's optional
	Comment  string       `json:"comment,omitempty"`  // Use omitempty as it's optional
	Includes *Condition   `json:"includes,omitempty"` // Use pointer and omitempty for optional object
	Excludes *Condition   `json:"excludes,omitempty"` // Use pointer and omitempty for optional object
}

func (sys *Syscall) convertAction(actionString string) seccomp.Action {
	var action seccomp.Action

	switch actionString {
	case "SCMP_ACT_ALLOW":
		action = seccomp.ActionAllow
	case "SCMP_ACT_ERRNO":
		action = seccomp.ActionErrno
	}
	return action
}

// ArchMapping represents the mapping between architectures.
type ArchMapping struct {
	Architecture     string   `json:"architecture"`
	SubArchitectures []string `json:"subArchitectures"` // Handles null as nil slice
}

// SeccompProfile represents the overall seccomp profile structure.
type SeccompProfile struct {
	DefaultAction   string        `json:"defaultAction"`
	DefaultErrnoRet int           `json:"defaultErrnoRet"`
	ArchMap         []ArchMapping `json:"archMap"`
	Syscalls        []Syscall     `json:"syscalls"`
}

func (profile *SeccompProfile) convertAction(actionString string) seccomp.Action {
	var action seccomp.Action

	switch actionString {
	case "SCMP_ACT_ALLOW":
		action = seccomp.ActionAllow
	case "SCMP_ACT_ERRNO":
		action = seccomp.ActionErrno
	}
	return action
}

func printBpfCode(inst []bpf.Instruction) {
	for i := 0; i < len(inst); i++ {
		//fmt.Printf("%v\n", inst[i])
		raw, _ := inst[i].Assemble()
		fmt.Printf("code: %02x, jt: %02x, jf: %02x, k: %08x\n", raw.Op, raw.Jt, raw.Jf, raw.K)
	}
}

func jsontToSeccompFilter(jsonpath string) {

	jsonData, err := os.ReadFile(jsonpath)
	if err != nil {
		log.Fatalf("Error reading file %s: %v", jsonpath, err)
	}

	var profile SeccompProfile
	err = json.Unmarshal(jsonData, &profile)
	if err != nil {
		log.Fatalf("Error unmarshalling JSON from file %s: %v\n", jsonpath, err)
	}

	for i, syscall := range profile.Syscalls {
		syscallGroup := seccomp.SyscallGroup{
			Action: syscall.convertAction(syscall.Action),
		}

		if len(syscall.Args) == 0 {
			syscallGroup.Names = syscall.Names
		} else {
			syscallGroup.NamesWithCondtions = []seccomp.NameWithConditions{
				{
					Name: syscall.Names[0],
					Conditions: []seccomp.Condition{
						{
							Argument:  uint32(syscall.Args[0].Index),
							Operation: syscall.Args[0].convertOp(syscall.Args[0].Op),
							Value:     syscall.Args[0].Value,
						},
					},
				},
			}
		}

		filter := seccomp.Filter{
			NoNewPrivs: true,
			Flag:       seccomp.FilterFlagTSync,
			Policy: seccomp.Policy{
				DefaultAction: profile.convertAction(profile.DefaultAction),
				Syscalls: []seccomp.SyscallGroup{
					syscallGroup,
				},
			},
		}
		inst, err := filter.Policy.Assemble()
		if err != nil {
			log.Fatalf("assemble failed: %v\n", err)
		}
		fmt.Printf("--- test case %d---\n", i)
		printBpfCode(inst)
		fmt.Printf("--- test case %d end\n", i)
	}
}

func main() {
	jsontToSeccompFilter("default_x86_64.json")
}

func _() {

	// Create a filter.
	filter := seccomp.Filter{
		NoNewPrivs: true,
		Flag:       seccomp.FilterFlagTSync,
		Policy: seccomp.Policy{
			DefaultAction: seccomp.ActionErrno,
			Syscalls: []seccomp.SyscallGroup{
				{
					Action: seccomp.ActionErrno,
					Names: []string{
						// "personality",
						"clone3",
					},
					//NamesWithCondtions: []seccomp.NameWithConditions{
					//	//{
					//	//	Name: "personality",
					//	//	Conditions: []seccomp.Condition{
					//	//		{
					//	//			Argument:  0,
					//	//			Operation: seccomp.Equal,
					//	//			Value:     8,
					//	//		},
					//	//	},
					//	//},
					//	{
					//		Name: "clone",
					//		Conditions: []seccomp.Condition{
					//			{
					//				Argument:  0,
					//				Operation: seccomp.LessOrEqual,
					//				Value:     2114060288,
					//			},
					//		},
					//	},
					//},
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
		fmt.Printf("code: %02x, jt: %02x, jf: %02x, k: %08x\n", raw.Op, raw.Jt, raw.Jf, raw.K)
	}
	//fmt.Printf("before load filter : %d\n", syscall.Getpid())
	// Load it. This will set no_new_privs before loading.
	if err := seccomp.LoadFilter(filter); err != nil {
		log.Fatal("failed to load filter: ", err)
	}
	fmt.Println("Load seccomp filter is OK")

	//fmt.Printf("after load filter : %d\n", syscall.Getpid())
}
