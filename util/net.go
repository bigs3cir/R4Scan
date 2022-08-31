package util

import (
	"fmt"
	"net"
)

func GetAvailablePort(port ...int) (int, error) {

	var (
		addr     *net.TCPAddr
		listener *net.TCPListener
		err      error
		ports    int
	)

	if len(port) > 1 {
		ports = port[0]
	}

	addr, err = net.ResolveTCPAddr("tcp", fmt.Sprintf("localhost:%d", ports))
	if err != nil {
		return 0, err
	}

	listener, err = net.ListenTCP("tcp", addr)
	if err != nil {
		return 0, err
	}

	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port, nil
}
