package core

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const maxPracticalJSONFrameBytes = 256 << 20

type practicalCountingReader struct {
	reader io.Reader
	read   int
}

func (reader *practicalCountingReader) Read(buffer []byte) (int, error) {
	n, err := reader.reader.Read(buffer)
	reader.read += n
	return n, err
}

func marshalPracticalJSONFrame(magic [2]byte, value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	if len(raw) > maxPracticalJSONFrameBytes {
		return nil, fmt.Errorf("Practical JSON wire too large: %d", len(raw))
	}
	payload := raw
	mode := byte(0)
	var compressed bytes.Buffer
	zw, err := gzip.NewWriterLevel(&compressed, gzip.BestSpeed)
	if err != nil {
		return nil, err
	}
	if _, err = zw.Write(raw); err != nil {
		_ = zw.Close()
		return nil, err
	}
	if err = zw.Close(); err != nil {
		return nil, err
	}
	if compressed.Len() < len(raw) {
		payload = compressed.Bytes()
		mode = 1
	}
	frame := make([]byte, 7+len(payload))
	copy(frame[:2], magic[:])
	frame[2] = mode
	binary.BigEndian.PutUint32(frame[3:7], uint32(len(payload)))
	copy(frame[7:], payload)
	return frame, nil
}

func readPracticalJSONFrame(reader io.Reader, magic [2]byte, value any) (int, error) {
	if value == nil {
		return 0, errors.New("nil Practical JSON wire")
	}
	counted := &practicalCountingReader{reader: reader}
	buffered := bufio.NewReader(counted)
	first, err := buffered.Peek(1)
	if err != nil {
		return counted.read, err
	}
	if first[0] != magic[0] {
		err = json.NewDecoder(buffered).Decode(value)
		return counted.read, err
	}
	header := make([]byte, 7)
	if _, err = io.ReadFull(buffered, header); err != nil {
		return counted.read, err
	}
	if header[0] != magic[0] || header[1] != magic[1] || header[2] > 1 {
		return counted.read, errors.New("invalid Practical JSON frame header")
	}
	payloadSize := int(binary.BigEndian.Uint32(header[3:7]))
	if payloadSize <= 0 || payloadSize > maxPracticalJSONFrameBytes {
		return counted.read, fmt.Errorf("invalid Practical JSON frame size: %d", payloadSize)
	}
	payload := make([]byte, payloadSize)
	if _, err = io.ReadFull(buffered, payload); err != nil {
		return counted.read, err
	}
	data := payload
	if header[2] == 1 {
		zr, openErr := gzip.NewReader(bytes.NewReader(payload))
		if openErr != nil {
			return counted.read, openErr
		}
		data, err = io.ReadAll(io.LimitReader(zr, maxPracticalJSONFrameBytes+1))
		closeErr := zr.Close()
		if err != nil {
			return counted.read, err
		}
		if closeErr != nil {
			return counted.read, closeErr
		}
		if len(data) > maxPracticalJSONFrameBytes {
			return counted.read, errors.New("decompressed Practical JSON wire too large")
		}
	}
	if err = json.Unmarshal(data, value); err != nil {
		return counted.read, err
	}
	return counted.read, nil
}
