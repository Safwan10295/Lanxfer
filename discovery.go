package main

import (
	"context"
	"net"
	"strconv"

	"github.com/libp2p/zeroconf/v2"
)

const mdnsService = "_lanxfer._tcp"

// advertise announces a receiver on the LAN until stop is called.
func advertise(name string, port int) (stop func(), err error) {
	srv, err := zeroconf.Register(name, mdnsService, "local.", port, []string{"v=1"}, nil)
	if err != nil {
		return nil, err
	}
	return srv.Shutdown, nil
}

// browse reports receivers until ctx ends.
func browse(ctx context.Context, found func(Peer)) error {
	entries := make(chan *zeroconf.ServiceEntry, 8)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for e := range entries {
			p := Peer{Name: e.Instance}
			port := strconv.Itoa(e.Port)
			// A receiver may advertise addresses we can't reach (virtual
			// adapters, other subnets); the sender tries them in order.
			for _, ip := range e.AddrIPv4 {
				p.Addrs = append(p.Addrs, net.JoinHostPort(ip.String(), port))
			}
			for _, ip := range e.AddrIPv6 {
				if !ip.IsLinkLocalUnicast() {
					p.Addrs = append(p.Addrs, net.JoinHostPort(ip.String(), port))
				}
			}
			if len(p.Addrs) > 0 {
				found(p)
			}
		}
	}()
	err := zeroconf.Browse(ctx, mdnsService, "local.", entries)
	if err != nil {
		return err
	}
	<-done
	return nil
}
