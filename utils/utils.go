package utils

import "net"

// Htons convert host byte order to network byte order
func Htons(value uint16) uint16 {
	return (value<<8)&0xff00 | (value>>8)&0x00ff
}

func GetInterfaceIndex(name string) (int, error) {
	nwdev, err := net.InterfaceByName(name)
	if err != nil {
		return 0, err
	}
	return nwdev.Index, nil
}
