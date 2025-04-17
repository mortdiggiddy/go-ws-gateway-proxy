package mqtt

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

// ParseMQTTConnect parses a raw MQTT CONNECT packet and returns the username and password (JWT)
func ParseMQTTConnect(packet []byte) (string, string, error) {
	const connectPacketType = 0x10

	if len(packet) < 2 {
		return "", "", errors.New("packet too short")
	}

	if packet[0] != connectPacketType {
		return "", "", fmt.Errorf("not a CONNECT packet (type 0x%x)", packet[0])
	}

	// Skip fixed header (byte 1 = remaining length)
	_, fixedHeaderLen := decodeVariableLength(packet[1:])
	buf := bytes.NewReader(packet[1+fixedHeaderLen:])

	// Protocol name
	protoName, err := readUTF8String(buf)
	if err != nil {
		return "", "", fmt.Errorf("failed to read protocol name: %w", err)
	}

	// Protocol version
	protoLevel, err := buf.ReadByte()
	if err != nil {
		return "", "", fmt.Errorf("failed to read protocol level: %w", err)
	}

	var mqttVersion string
	switch protoLevel {
	case 4:
		mqttVersion = "3.1.1"
	case 5:
		mqttVersion = "5.0"
	default:
		return "", "", fmt.Errorf("unsupported MQTT version: %d", protoLevel)
	}

	// Connect flags
	connectFlags, err := buf.ReadByte()
	if err != nil {
		return "", "", fmt.Errorf("failed to read connect flags: %w", err)
	}
	usernameFlag := (connectFlags & 0x80) != 0
	passwordFlag := (connectFlags & 0x40) != 0

	// Keep alive
	if _, err := buf.Seek(2, 1); err != nil {
		return "", "", fmt.Errorf("failed to skip keepalive: %w", err)
	}

	// MQTT 5.0 only: skip "properties" field (variable length)
	if protoLevel == 5 {
		propLen, _, err := readVarInt(buf)
		if err != nil {
			return "", "", fmt.Errorf("failed to read properties length: %w", err)
		}
		if _, err := buf.Seek(int64(propLen), 1); err != nil {
			return "", "", fmt.Errorf("failed to skip properties: %w", err)
		}
	}

	// Client ID
	_, err = readUTF8String(buf)
	if err != nil {
		return "", "", fmt.Errorf("failed to read client ID: %w", err)
	}

	// Optional fields
	var username, password string

	if connectFlags&0x02 != 0 { // Will Flag
		if _, err := readUTF8String(buf); err != nil {
			return "", "", fmt.Errorf("failed to read will topic: %w", err)
		}
		if _, err := readUTF8String(buf); err != nil {
			return "", "", fmt.Errorf("failed to read will message: %w", err)
		}
	}

	if usernameFlag {
		username, err = readUTF8String(buf)
		if err != nil {
			return "", "", fmt.Errorf("failed to read username: %w", err)
		}
	}

	if passwordFlag {
		password, err = readUTF8String(buf)
		if err != nil {
			return "", "", fmt.Errorf("failed to read password: %w", err)
		}
	}

	if password == "" {
		return "", "", errors.New("password (JWT) missing")
	}

	return username, password, nil
}

// decodeVariableLength reads MQTT-style variable-length int and returns the decoded length and bytes consumed
func decodeVariableLength(data []byte) (int, int) {
	var value, multiplier int

	for i := 0; i < len(data); i++ {
		encodedByte := data[i]
		value += int(encodedByte&127) << (7 * multiplier)
		multiplier++
		if encodedByte&128 == 0 { 
			return value, multiplier
		}
	}
	return 0, 0
}

// readUTF8String reads an MQTT-style UTF-8 string: 2-byte length prefix followed by bytes
func readUTF8String(buf *bytes.Reader) (string, error) {
	var length uint16
	if err := binary.Read(buf, binary.BigEndian, &length); err != nil {
		return "", err
	}
	strBytes := make([]byte, length)
	if _, err := buf.Read(strBytes); err != nil {
		return "", err
	}
	return string(strBytes), nil
}

func readVarInt(buf *bytes.Reader) (int, int, error) {
	value := 0
	multiplier := 1
	consumed := 0
	for {
		b, err := buf.ReadByte()
		if err != nil {
			return 0, consumed, err
		}
		value += int(b&127) * multiplier
		consumed++
		if b&128 == 0 {
			break
		}
		multiplier *= 128
		if multiplier > 128*128*128 {
			return 0, consumed, errors.New("malformed variable integer")
		}
	}
	return value, consumed, nil
}

