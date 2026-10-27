package machimage

import "io"

type sliceReaderAt struct {
	data []byte
}

func (s sliceReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || off >= int64(len(s.data)) {
		return 0, io.EOF
	}
	n := copy(p, s.data[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func bytesReaderAt(b []byte) sliceReaderAt { return sliceReaderAt{data: b} }
