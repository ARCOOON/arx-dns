package network

import (
	"context"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

func listenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	lc := net.ListenConfig{
		Control: reusePortControl(network),
	}
	return lc.ListenPacket(ctx, network, address)
}

func listenTCP(ctx context.Context, network, address string) (net.Listener, error) {
	lc := net.ListenConfig{
		Control: reusePortControl(network),
	}
	return lc.Listen(ctx, network, address)
}

func reusePortControl(network string) func(network, address string, conn syscall.RawConn) error {
	return func(_, _ string, conn syscall.RawConn) error {
		var ctrlErr error
		err := conn.Control(func(fd uintptr) {
			ctrlErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
			if ctrlErr != nil {
				return
			}
			ctrlErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
			if ctrlErr != nil {
				return
			}
			if network == "tcp" || network == "udp" {
				ctrlErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_V6ONLY, 0)
			}
		})
		if err != nil {
			return err
		}
		return ctrlErr
	}
}
