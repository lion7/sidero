// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package dhcp

import (
	"errors"
	"fmt"
	"log"
	"net"

	"go.universe.tf/netboot/dhcp4"
)

func ServeDHCP() error {
	conn, err := dhcp4.NewConn("0.0.0.0:67")
	if err != nil {
		return err
	}

	for {
		pkt, intf, err := conn.RecvDHCP()
		if err != nil {
			return fmt.Errorf("receiving DHCP packet: %s", err)
		}
		if intf == nil {
			return fmt.Errorf("received DHCP packet with no interface information (this is a violation of dhcp4.Conn's contract, please file a bug)")
		}

		if err = isBootDHCP(pkt); err != nil {
			//log.Printf("[DHCP] Ignoring packet from %s: %s", pkt.HardwareAddr, err) // should be debug logging
			continue
		}

		fwtype, err := validateDHCP(pkt)
		if err != nil {
			log.Printf("[DHCP] Unusable packet from %s: %s", pkt.HardwareAddr, err)
			continue
		}

		serverIP, err := interfaceIP(intf)
		if err != nil {
			log.Printf("[DHCP] Want to boot %s on %s, but couldn't get a source address: %s", pkt.HardwareAddr, intf.Name, err)
			continue
		}

		resp, err := offerDHCP(pkt, serverIP, fwtype)
		if err != nil {
			log.Printf("[DHCP] Failed to construct ProxyDHCP offer for %s: %s", pkt.HardwareAddr, err)
			continue
		}

		log.Printf("[DHCP] Offering to boot %s from %s with filename %q", pkt.HardwareAddr, resp.BootServerName, resp.BootFilename)
		if err = conn.SendDHCP(resp, intf); err != nil {
			log.Printf("[DHCP] Failed to send ProxyDHCP offer for %s: %s", pkt.HardwareAddr, err)
			continue
		}
	}
}

func isBootDHCP(pkt *dhcp4.Packet) error {
	if pkt.Type != dhcp4.MsgDiscover {
		return fmt.Errorf("packet is %s, not %s", pkt.Type, dhcp4.MsgDiscover)
	}

	if pkt.Options[93] == nil {
		return errors.New("not a PXE boot request (missing option 93)")
	}

	return nil
}

func validateDHCP(pkt *dhcp4.Packet) (fwtype Firmware, err error) {
	fwt, err := pkt.Options.Uint16(93)
	if err != nil {
		return 0, fmt.Errorf("malformed DHCP option 93 (required for PXE): %s", err)
	}

	// Basic architecture and firmware identification, based purely on
	// the PXE architecture option.
	switch fwt {
	case 0:
		fwtype = FirmwareX86PC
	case 6:
		fwtype = FirmwareEFI32
	case 7:
		fwtype = FirmwareEFI64
	case 9:
		fwtype = FirmwareEFIBC
	default:
		return 0, fmt.Errorf("unsupported client firmware type '%d' (please file a bug!)", fwtype)
	}

	// Now, identify special sub-breeds of client firmware based on
	// the user-class option. Note these only change the "firmware
	// type", not the architecture we're reporting to Booters. We need
	// to identify these as part of making the internal chainloading
	// logic work properly.
	if userClass, err := pkt.Options.String(77); err == nil {
		// If the client has had iPXE burned into its ROM (or is a VM
		// that uses iPXE as the PXE "ROM"), special handling is
		// needed because in this mode the client is using iPXE native
		// drivers and chainloading to a UNDI stack won't work.
		if userClass == "iPXE" && fwtype == FirmwareX86PC {
			fwtype = FirmwareX86Ipxe
		}
	}

	guid := pkt.Options[97]
	switch len(guid) {
	case 0:
		// A missing GUID is invalid according to the spec, however
		// there are PXE ROMs in the wild that omit the GUID and still
		// expect to boot. The only thing we do with the GUID is
		// mirror it back to the client if it's there, so we might as
		// well accept these buggy ROMs.
	case 17:
		if guid[0] != 0 {
			return 0, errors.New("malformed client GUID (option 97), leading byte must be zero")
		}
	default:
		return 0, errors.New("malformed client GUID (option 97), wrong size")
	}

	return fwtype, nil
}

func offerDHCP(pkt *dhcp4.Packet, serverIP net.IP, fwtype Firmware) (*dhcp4.Packet, error) {
	mac := pkt.HardwareAddr
	resp := &dhcp4.Packet{
		Type:          dhcp4.MsgOffer,
		TransactionID: pkt.TransactionID,
		Broadcast:     true,
		HardwareAddr:  mac,
		RelayAddr:     pkt.RelayAddr,
		ServerAddr:    serverIP,
		Options:       make(dhcp4.Options),
	}
	resp.Options[dhcp4.OptServerIdentifier] = serverIP
	// says the server should identify itself as a PXEClient vendor
	// type, even though it's a server. Strange.
	if pkt.Options[dhcp4.OptVendorIdentifier] != nil {
		resp.Options[dhcp4.OptVendorIdentifier] = pkt.Options[dhcp4.OptVendorIdentifier]
	} else {
		resp.Options[dhcp4.OptVendorIdentifier] = []byte("PXEClient")
	}
	if pkt.Options[97] != nil {
		resp.Options[97] = pkt.Options[97]
	}

	// Bypass all the boot discovery rubbish that PXE supports,
	pxe := dhcp4.Options{
		// PXE Boot Server Discovery Control - bypass, just boot from filename.
		6: []byte{8},
	}
	bs, err := pxe.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize PXE vendor options: %s", err)
	}
	resp.Options[43] = bs

	switch fwtype {
	case FirmwareX86PC:
		// This is completely standard PXE: just load a file from TFTP.
		resp.BootServerName = serverIP.String()
		resp.BootFilename = "undionly.kpxe"

	case FirmwareX86Ipxe:
		// Almost standard PXE, but the boot filename needs to be a URL.
		resp.BootFilename = fmt.Sprintf("tftp://%s/ipxe.efi", serverIP)

	case FirmwareEFI32, FirmwareEFI64, FirmwareEFIBC:
		// This is completely standard PXE: just load a file from TFTP.
		resp.BootServerName = serverIP.String()
		resp.BootFilename = "ipxe.efi"

	default:
		return nil, fmt.Errorf("unknown firmware type %d", fwtype)
	}

	return resp, nil
}

func interfaceIP(intf *net.Interface) (net.IP, error) {
	addrs, err := intf.Addrs()
	if err != nil {
		return nil, err
	}

	// Try to find an IPv4 address to use, in the following order:
	// global unicast (includes rfc1918), link-local unicast,
	// loopback.
	fs := [](func(net.IP) bool){
		net.IP.IsGlobalUnicast,
		net.IP.IsLinkLocalUnicast,
		net.IP.IsLoopback,
	}
	for _, f := range fs {
		for _, a := range addrs {
			ipaddr, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipaddr.IP.To4()
			if ip == nil {
				continue
			}
			if f(ip) {
				return ip, nil
			}
		}
	}

	return nil, errors.New("no usable unicast address configured on interface")
}

// Firmware describes a kind of firmware attempting to boot.
//
// This should only be used for selecting the right bootloader,
// kernel selection should key off the more generic architecture.
type Firmware int

// The bootloaders that we know how to handle.
const (
	FirmwareX86PC   Firmware = iota // "Classic" x86 BIOS with PXE/UNDI support
	FirmwareEFI32                   // 32-bit x86 processor running EFI
	FirmwareEFI64                   // 64-bit x86 processor running EFI
	FirmwareEFIBC                   // 64-bit x86 processor running EFI
	FirmwareX86Ipxe                 // "Classic" x86 BIOS running iPXE (no UNDI support)
)
