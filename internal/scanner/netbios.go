package scanner

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"log"
	"net"
	"strings"
)

const (
	netbiosPort   = 137
	netbiosNBSTAT = 0x0021
	netbiosIN     = 0x0001
	// netbiosGroupFlag marks a name as a workgroup rather than the machine.
	netbiosGroupFlag = 0x8000
	// netbiosWorkstation is the suffix of the record holding the machine name.
	netbiosWorkstation = 0x00
)

// lookupNetBIOS asks the host itself for its NetBIOS name table. Windows
// machines that publish neither mDNS nor a DHCP hostname still answer this.
func lookupNetBIOS(ctx context.Context, ip net.IP, l *link) string {
	var txID [2]byte
	if _, err := rand.Read(txID[:]); err != nil {
		log.Printf("netbios transaction id: %v", err)
		return ""
	}

	conn, err := dialUDP(ctx, l, &net.UDPAddr{IP: ip, Port: netbiosPort})
	if err != nil {
		return ""
	}
	defer closeConn(conn, "netbios")

	query := netbiosStatusQuery(txID)
	buf := make([]byte, 2048)
	return udpRetry(ctx, netbiosRetry, conn.SetReadDeadline,
		func() error {
			_, err := conn.Write(query)
			return err
		},
		func() (string, error) {
			n, err := conn.Read(buf)
			if err != nil {
				return "", err
			}
			if n < 12 || buf[0] != txID[0] || buf[1] != txID[1] {
				return "", nil
			}
			return parseNetBIOSStatus(buf[:n]), nil
		})
}

func netbiosStatusQuery(txID [2]byte) []byte {
	msg := make([]byte, 0, 50)
	msg = append(msg, txID[0], txID[1])
	msg = append(msg, 0x00, 0x00) // flags: standard query, no recursion
	msg = append(msg, 0x00, 0x01) // one question
	msg = append(msg, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	msg = append(msg, 0x20) // label length: names always encode to 32 bytes
	msg = append(msg, encodeNetBIOSName("*")...)
	msg = append(msg, 0x00) // root label
	msg = binary.BigEndian.AppendUint16(msg, netbiosNBSTAT)
	msg = binary.BigEndian.AppendUint16(msg, netbiosIN)
	return msg
}

// encodeNetBIOSName applies first-level encoding: the name is padded to 16
// bytes and each nibble becomes a letter starting at 'A'.
func encodeNetBIOSName(name string) []byte {
	raw := make([]byte, 16)
	copy(raw, name)

	out := make([]byte, 0, 32)
	for _, b := range raw {
		out = append(out, 'A'+(b>>4), 'A'+(b&0x0f))
	}
	return out
}

func parseNetBIOSStatus(msg []byte) string {
	if binary.BigEndian.Uint16(msg[6:8]) == 0 {
		return ""
	}

	pos := 12
	for i := 0; i < int(binary.BigEndian.Uint16(msg[4:6])); i++ {
		if pos = skipNetBIOSName(msg, pos); pos < 0 {
			return ""
		}
		pos += 4 // question type and class
	}

	if pos = skipNetBIOSName(msg, pos); pos < 0 {
		return ""
	}
	pos += 2 + 2 + 4 + 2 // type, class, ttl, rdlength
	if pos >= len(msg) {
		return ""
	}

	count := int(msg[pos])
	pos++
	for i := 0; i < count; i++ {
		// 15 name bytes, a one byte service suffix, then two flag bytes.
		if pos+18 > len(msg) {
			break
		}
		entry := msg[pos : pos+15]
		suffix := msg[pos+15]
		flags := binary.BigEndian.Uint16(msg[pos+16 : pos+18])
		pos += 18

		if flags&netbiosGroupFlag != 0 || suffix != netbiosWorkstation {
			continue
		}
		if name := strings.TrimRight(string(entry), " \x00"); name != "" {
			return name
		}
	}
	return ""
}

func skipNetBIOSName(msg []byte, pos int) int {
	for pos >= 0 && pos < len(msg) {
		length := int(msg[pos])
		switch {
		case length == 0:
			return pos + 1
		case length&0xC0 == 0xC0:
			return pos + 2 // compression pointer
		default:
			pos += 1 + length
		}
	}
	return -1
}
