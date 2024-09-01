package main

import (
	"fmt"
	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
	"log"
	"syscall"
	"unsafe"

	// #include <linux/audit.h>
	// #include <linux/seccomp.h>
	"C"
)

func toSockFprog(inst []bpf.Instruction) *syscall.SockFprog {

	var sockFilter []syscall.SockFilter

	for i := 0; i < len(inst); i++ {
		rawinst, err := inst[i].Assemble()
		if err != nil {
			log.Fatal("assemble error:", err)
		}
		sockFilter = append(sockFilter, syscall.SockFilter{
			Code: rawinst.Op,
			Jt:   rawinst.Jt,
			Jf:   rawinst.Jf,
			K:    rawinst.K,
		})
	}

	program := &syscall.SockFprog{
		Len:    uint16(len(sockFilter)),
		Filter: &sockFilter[0],
	}
	return program
}

func main() {
	_, _, errno := syscall.Syscall6(syscall.SYS_PRCTL, unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0, 0)
	if errno != 0 {
		log.Fatal("prctl failed : ", errno)
	}

	var data C.struct_seccomp_data

	instruction := []bpf.Instruction{
		bpf.LoadAbsolute{
			Off:  uint32(unsafe.Offsetof(data.arch)),
			Size: 4,
		},
		bpf.JumpIf{
			Cond:      bpf.JumpNotEqual,
			Val:       C.AUDIT_ARCH_X86_64,
			SkipTrue:  4,
			SkipFalse: 0,
		},
		bpf.RetConstant{Val: 0},
		bpf.LoadAbsolute{
			Off:  0,
			Size: 4,
		},
		bpf.JumpIf{
			Cond: bpf.JumpNotEqual,
			// getpid = 39
			Val:       39,
			SkipTrue:  1,
			SkipFalse: 0,
		},
		bpf.RetConstant{Val: C.SECCOMP_RET_KILL},
		bpf.RetConstant{Val: C.SECCOMP_RET_ALLOW},
	}

	for i := 0; i < len(instruction); i++ {
		fmt.Printf("%v\n", instruction[i])
		raw, _ := instruction[i].Assemble()
		fmt.Printf("%v, %v, %v, %v\n", raw.Op, raw.Jt, raw.Jf, raw.K)
	}

	filterPgm := toSockFprog(instruction)
	_, _, errno = syscall.Syscall(unix.SYS_SECCOMP, C.SECCOMP_SET_MODE_FILTER, 0, uintptr(unsafe.Pointer(filterPgm)))
	if errno != 0 {
		log.Fatal("seccomp failed : ", errno)
	}
	syscall.Getpid()
}
