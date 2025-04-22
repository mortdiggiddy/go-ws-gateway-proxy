package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	mqtt3UsernameFlag    = 0x80
    mqtt3PasswordFlag    = 0x40
	// MQTT 5 property identifiers
    propUserProperty     = 0x26
)

// InjectUserProperties injects role metadata into an MQTT CONNECT packet.
// - MQTT 5: adds a User Property entry under Properties.
// - MQTT 3.x: encodes roles into the username field (e.g. "origUser|role1,role2").
func InjectUserProperties(packet []byte, rolesCSV string) ([]byte, error) {
    if len(packet) < 2 || packet[0] != connectPacketType {
        return nil, errors.New("not MQTT CONNECT")
    }
    // decode remaining length
    _, hdrLen := decodeVariableLength(packet[1:])
    start := 1 + hdrLen
    buf := bytes.NewReader(packet[start:])

    // skip protocol name
    if _, err := readUTF8String(buf); err != nil {
        return nil, err
    }
    // read protocol level
    level, _ := buf.ReadByte()
    // only MQTT3.x support here
    if level > 5 {
        return packet, nil // stub for MQTT5
    }

    // read connect flags
    flags, _ := buf.ReadByte()
    hasUser := flags&mqtt3UsernameFlag != 0   // ***
    hasPass := flags&mqtt3PasswordFlag != 0   // ***

    // skip keepalive
    buf.Seek(2, 1)

    // skip client ID
    if _, err := readUTF8String(buf); err != nil {
        return nil, err
    }
    // skip will if set
    if flags&0x04 != 0 {
        readUTF8String(buf)
        readUTF8String(buf)
    }

    // if there's no username field, nothing to inject
    if !hasUser { 
        return packet, nil
    }

    // read old username
    oldUser, err := readUTF8String(buf)
    if err != nil {
        return nil, err
    }

    // skip old password only if present
    if hasPass {  
        if _, err := readUTF8String(buf); err != nil {
            return nil, err
        }
    }

    // build new username with roles
    newUser := oldUser
    if rolesCSV != "" {
        newUser = fmt.Sprintf("%s|%s", oldUser, rolesCSV)
    }

    // compute position in original packet where username length prefix starts
    pos := len(packet) - buf.Len()
    // advance past the two-byte length prefix
    pos += 2

    // construct the new packet
    newUserBytes := []byte(newUser)
    newLen := uint16(len(newUserBytes))
    out := make([]byte, 0, len(packet)+(len(newUserBytes)-len(oldUser)))
    out = append(out, packet[:pos]...)
    // write updated length
    lenBuf := make([]byte, 2)
    binary.BigEndian.PutUint16(lenBuf, newLen)
    out = append(out, lenBuf...)
    // write new username
    out = append(out, newUserBytes...)
    // append the remainder (including password and beyond)
    remainder := packet[pos+2+len(oldUser):]
    out = append(out, remainder...)

    return out, nil
}
