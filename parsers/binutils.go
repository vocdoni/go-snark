package parsers

import (
	"bufio"
	"encoding/binary"
	"fmt"
)

func readHeaderBinFile(r *bufio.Reader) (int, error) {
	b := make([]byte, 4)
	if _, err := r.Read(b); err != nil {
		return 0, err
	}
	fmt.Println("file type", string(b))

	b = make([]byte, 8)
	if _, err := r.Read(b); err != nil {
		return 0, err
	}
	version := int(binary.LittleEndian.Uint32(b[:4]))
	nSections := int(binary.LittleEndian.Uint32(b[4:8]))
	fmt.Println("version", version)
	fmt.Println("nSections", nSections)

	return nSections, nil
}

type binSection struct {
	typ  int
	size int
}

func readHeaderBinSection(r *bufio.Reader) (int, error) {
	b := make([]byte, 4+8)
	if _, err := r.Read(b); err != nil {
		return 0, err
	}
	sectionType := int(binary.LittleEndian.Uint32(b[:4]))
	fmt.Println("sectionType", sectionType)
	sectionBodySize := int(binary.LittleEndian.Uint64(b[4:12]))
	fmt.Println("sectionBodySize", sectionBodySize)
	return sectionBodySize, nil
}
