package shred

import (
	"os"
	"time"

	"golang.org/x/exp/rand"
)

func SevenPass(loc string) error {
	file, err := os.OpenFile(loc, os.O_RDWR, 0)
	if err != nil {
		return err
	}

	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return err
	}

	size := info.Size()

	patterns := [][]byte{
		{0x00},
		{0xFF},
		{0x55},
		{0xAA},
		{0x92},
		{0x49},
		{0x24},
	}

	for passIndex := 0; passIndex < 7; passIndex++ {
		if err := pattern(file, size, patterns[passIndex]); err != nil {
			return err
		}

		if err := file.Sync(); err != nil {
			return err
		}
	}

	if err := random(file, size); err != nil {
		return err
	}

	if err := file.Sync(); err != nil {
		return err
	}

	return nil
}

func pattern(file *os.File, size int64, pattern []byte) error {
	buffer := make([]byte, len(pattern))
	for patternIndex := int64(0); patternIndex < size; patternIndex += int64(len(pattern)) {
		copy(buffer, pattern)
		if _, err := file.WriteAt(buffer, patternIndex); err != nil {
			return err
		}
	}

	return nil
}

func random(file *os.File, size int64) error {
	rand.Seed(uint64(time.Now().UnixNano()))

	buffer := make([]byte, 4096)
	for bufferIndex := int64(0); bufferIndex < size; bufferIndex += int64(len(buffer)) {
		if _, err := rand.Read(buffer); err != nil {
			return err
		}

		if _, err := file.WriteAt(buffer, bufferIndex); err != nil {
			return err
		}
	}

	return nil
}
