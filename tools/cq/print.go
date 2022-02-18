package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"time"
)

func print(indent int, r io.Reader, width int, prefix string) error {
	majorType, count, content, err := readHeader(r)
	if err != nil {
		return err
	}

	switch majorType {
	case 0, 1:
		n := int64(count)
		if majorType == 1 {
			n = -n
		}
		desc := fmt.Sprintf("Integer: %d", n)
		println(indent, content, width, prefix+desc)
	case 2:
		desc := fmt.Sprintf("Binary string: %d bytes", count)
		println(indent, content, width, prefix+desc)
		return printString(indent+1, r, count)
	case 3:
		desc := fmt.Sprintf("UTF-8 text: %d bytes", count)
		println(indent, content, width, prefix+desc)
		return printString(indent+1, r, count)
	case 4:
		desc := fmt.Sprintf("Array of length %d", count)
		println(indent, content, width, prefix+desc)
		for i := uint64(0); i < count; i++ {
			if err := print(indent+1, r, 0, ""); err != nil {
				return err
			}
		}
	case 5:
		desc := fmt.Sprintf("Map of size %d", count)
		println(indent, content, 0, prefix+desc)
		for i := uint64(0); i < count; i++ {
			if err := print(indent+1, r, 3, "Key:   "); err != nil {
				return err
			}
			if err := print(indent+1, r, 3, "Value: "); err != nil {
				return err
			}
		}
	case 6:
		return printTag(indent, r, content, count, prefix)
	default:
		return fmt.Errorf("major type %d is not supported", majorType)
	}
	return nil
}

func printString(indent int, r io.Reader, count uint64) error {
	var buf [16]byte
	for count > 0 {
		n := count
		if n > 16 {
			n = 16
		}
		line := buf[:n]
		if _, err := io.ReadFull(r, line); err != nil {
			return err
		}
		b := strings.Builder{}
		for _, c := range line {
			if c > 0x1f && c < 0x7f {
				b.WriteByte(c)
			} else {
				b.WriteByte('.')
			}
		}
		println(indent, line, 16, b.String())
		count -= n
	}
	return nil
}

func printTag(indent int, r io.Reader, content []byte, tag uint64, prefix string) error {
	desc := fmt.Sprintf("%sTag %d", prefix, tag)
	switch tag {
	case 1:
		desc += ": datetime"
		println(indent, content, 0, desc)
		return printDateTime(indent, r)
	case 18:
		desc += ": cose-sign1"
		println(indent, content, 0, desc)
		return printCOSESign1(indent, r)
	default:
		println(indent, content, 0, desc)
		return print(indent, r, 0, "")
	}
}

func printCOSESign1(indent int, r io.Reader) error {
	_, _, content, err := readHeader(r)
	if err != nil {
		return err
	}
	if !bytes.Equal(content, []byte{0x84}) {
		return fmt.Errorf("invalid COSE Sign1 object: %v", content)
	}
	desc := "COSE_Sign1 object: Array of length 4"
	println(indent, content, 0, desc)
	indent++

	// protected header
	majorType, count, content, err := readHeader(r)
	if err != nil {
		return err
	}
	if majorType != 2 {
		return fmt.Errorf("invalid protected header: %v", content)
	}
	desc = fmt.Sprintf("protected: Binary string: %d bytes", count)
	println(indent, content, 0, desc)
	if err := print(indent+1, r, 0, ""); err != nil {
		return err
	}

	// unprotected header
	if err := print(indent, r, 0, "unprotected: "); err != nil {
		return err
	}

	// payload
	if err := print(indent, r, 0, "payload: "); err != nil {
		return err
	}

	// signature
	if err := print(indent, r, 0, "signature: "); err != nil {
		return err
	}

	return nil
}

func printDateTime(indent int, r io.Reader) error {
	majorType, count, content, err := readHeader(r)
	if err != nil {
		return err
	}
	if majorType != 0 {
		return fmt.Errorf("datetime type %d not supported", majorType)
	}

	t := time.Unix(int64(count), 0).UTC()
	desc := fmt.Sprintf("UNIX epoch: %d -> %s", count, t.Format(time.RFC3339))
	println(indent, content, 0, desc)
	return nil
}

func readHeader(r io.Reader) (byte, uint64, []byte, error) {
	contentBuffer := bytes.NewBuffer(nil)
	r = io.TeeReader(r, contentBuffer)

	var header [1]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return 0, 0, nil, err
	}

	majorType := header[0] >> 5
	count := uint64(header[0] & 0x1f)
	if count > 27 {
		return 0, 0, nil, fmt.Errorf("invalid count: %d", count)
	}
	switch count {
	case 24:
		var counts [1]byte
		if _, err := io.ReadFull(r, counts[:]); err != nil {
			return 0, 0, nil, err
		}
		count = uint64(counts[0])
	case 25:
		var counts [2]byte
		if _, err := io.ReadFull(r, counts[:]); err != nil {
			return 0, 0, nil, err
		}
		count = uint64(binary.BigEndian.Uint16(counts[:]))
	case 26:
		var counts [4]byte
		if _, err := io.ReadFull(r, counts[:]); err != nil {
			return 0, 0, nil, err
		}
		count = uint64(binary.BigEndian.Uint32(counts[:]))
	case 27:
		var counts [8]byte
		if _, err := io.ReadFull(r, counts[:]); err != nil {
			return 0, 0, nil, err
		}
		count = binary.BigEndian.Uint64(counts[:])
	}

	return majorType, count, contentBuffer.Bytes(), nil
}

func println(indent int, content []byte, width int, description string) {
	for i := 0; i < indent; i++ {
		fmt.Printf("   ")
	}
	for _, c := range content {
		fmt.Printf("%02x ", c)
	}
	padding := width - len(content)
	for i := 0; i < padding; i++ {
		fmt.Printf("   ")
	}
	fmt.Println("--", description)
}
