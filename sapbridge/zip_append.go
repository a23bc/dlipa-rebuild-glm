package sapbridge

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"os"
)

// Appending entries instead of rewriting the archive.
//
// Rebuilding every entry through archive/zip produces a valid zip, but not the same
// one: Apple's packages carry an alignment record (extra field 0x5a53) in each
// entry's *local* header, and the central directory does not describe it. A rewrite
// therefore silently drops the alignment of all four thousand entries, and the
// installer refuses the result after downloading it in full.
//
// This keeps the original bytes exactly as they are and only appends: the new local
// records go after the last entry, and the central directory is reproduced verbatim
// with the new records inserted. Nothing that was already there moves.

// extraEntry is a file to add.
type extraEntry struct {
	Name string
	Data []byte
}

// appendToZip writes src to dst with entries appended.
func appendToZip(srcPath, dstPath string, entries []extraEntry) error {
	source, err := os.Open(srcPath)
	if err != nil {
		return fmt.Errorf("open source: %w", err)
	}

	defer source.Close()

	info, err := source.Stat()
	if err != nil {
		return fmt.Errorf("stat source: %w", err)
	}

	if info.Size() < 22 {
		return fmt.Errorf("source is too small to be a zip")
	}

	directory, err := readDirectory(source, info.Size())
	if err != nil {
		return err
	}

	existing := directory.names()

	target, err := os.Create(dstPath)
	if err != nil {
		return fmt.Errorf("create target: %w", err)
	}

	defer target.Close()

	writer := newWriter(target)

	// Everything up to the central directory is copied verbatim, which keeps every
	// existing local header -- and its alignment record -- byte for byte.
	if _, err := io.CopyN(writer, source, directory.offset); err != nil {
		return fmt.Errorf("copy payload: %w", err)
	}

	var appended []centralRecord

	for _, entry := range entries {
		if _, seen := existing[entry.Name]; seen {
			// Already present: the package came patched, leave it alone.
			continue
		}

		offset := writer.written

		record, err := writeLocalEntry(writer, entry, offset)
		if err != nil {
			return err
		}

		appended = append(appended, record)
	}

	centralStart := writer.written

	// The original directory, untouched.
	if _, err := io.CopyN(writer, source, directory.size); err != nil {
		return fmt.Errorf("copy directory: %w", err)
	}

	for _, record := range appended {
		if err := writeCentralRecord(writer, record); err != nil {
			return err
		}
	}

	centralSize := writer.written - centralStart

	if err := writeDirectoryEnd(writer, len(directory.records)+len(appended), centralStart, centralSize, directory.comment); err != nil {
		return err
	}

	if err := writer.err; err != nil {
		return err
	}

	return target.Sync()
}

// zipDirectory is the locating information for the archive's central directory.
type zipDirectory struct {
	offset  int64
	size    int64
	records []centralRecord
	comment []byte
}

// centralRecord is what is needed to detect duplicates and to write a new entry.
type centralRecord struct {
	Name         string
	CRC          uint32
	Compressed   uint32
	Uncompressed uint32
	Method       uint16
	ModifiedTime uint16
	ModifiedDate uint16
	LocalOffset  uint32
}

func (d zipDirectory) names() map[string]struct{} {
	names := make(map[string]struct{}, len(d.records))
	for _, record := range d.records {
		names[record.Name] = struct{}{}
	}

	return names
}

// readDirectory finds the end-of-directory record and walks the records.
func readDirectory(source *os.File, size int64) (zipDirectory, error) {
	const tail = 66 * 1024

	start := size - tail
	if start < 0 {
		start = 0
	}

	buffer := make([]byte, size-start)
	if _, err := source.ReadAt(buffer, start); err != nil {
		return zipDirectory{}, fmt.Errorf("read tail: %w", err)
	}

	index := bytes.LastIndex(buffer, []byte{'P', 'K', 0x05, 0x06})
	if index < 0 {
		return zipDirectory{}, fmt.Errorf("no end of central directory record")
	}

	end := buffer[index:]
	if len(end) < 22 {
		return zipDirectory{}, fmt.Errorf("truncated end record")
	}

	count := int(binary.LittleEndian.Uint16(end[10:12]))
	directorySize := int64(binary.LittleEndian.Uint32(end[12:16]))
	directoryOffset := int64(binary.LittleEndian.Uint32(end[16:20]))
	commentLength := int(binary.LittleEndian.Uint16(end[20:22]))

	if int64(len(end)) < int64(22+commentLength) {
		return zipDirectory{}, fmt.Errorf("truncated comment")
	}

	record := make([]byte, directorySize)
	if _, err := source.ReadAt(record, directoryOffset); err != nil {
		return zipDirectory{}, fmt.Errorf("read directory: %w", err)
	}

	records, err := parseCentralRecords(record, count)
	if err != nil {
		return zipDirectory{}, err
	}

	return zipDirectory{
		offset:  directoryOffset,
		size:    directorySize,
		records: records,
		comment: end[22 : 22+commentLength],
	}, nil
}

func parseCentralRecords(raw []byte, count int) ([]centralRecord, error) {
	records := make([]centralRecord, 0, count)
	cursor := 0

	for len(records) < count {
		if cursor+46 > len(raw) {
			return nil, fmt.Errorf("central directory truncated at record %d", len(records))
		}

		if binary.LittleEndian.Uint32(raw[cursor:]) != 0x02014b50 {
			return nil, fmt.Errorf("bad central signature at %d", cursor)
		}

		nameLength := int(binary.LittleEndian.Uint16(raw[cursor+28:]))
		extraLength := int(binary.LittleEndian.Uint16(raw[cursor+30:]))
		commentLength := int(binary.LittleEndian.Uint16(raw[cursor+32:]))

		start := cursor + 46
		if start+nameLength > len(raw) {
			return nil, fmt.Errorf("central name out of range")
		}

		records = append(records, centralRecord{
			Name:         string(raw[start : start+nameLength]),
			CRC:          binary.LittleEndian.Uint32(raw[cursor+16:]),
			Compressed:   binary.LittleEndian.Uint32(raw[cursor+20:]),
			Uncompressed: binary.LittleEndian.Uint32(raw[cursor+24:]),
			Method:       binary.LittleEndian.Uint16(raw[cursor+10:]),
			ModifiedTime: binary.LittleEndian.Uint16(raw[cursor+12:]),
			ModifiedDate: binary.LittleEndian.Uint16(raw[cursor+14:]),
			LocalOffset:  binary.LittleEndian.Uint32(raw[cursor+42:]),
		})

		cursor = start + nameLength + extraLength + commentLength
	}

	return records, nil
}

// writeLocalEntry writes header and compressed data, returning the record that the
// central directory will need.
func writeLocalEntry(writer *countingWriter, entry extraEntry, offset int64) (centralRecord, error) {
	var compressed bytes.Buffer

	deflater, err := flate.NewWriter(&compressed, flate.DefaultCompression)
	if err != nil {
		return centralRecord{}, fmt.Errorf("deflate %s: %w", entry.Name, err)
	}

	if _, err := deflater.Write(entry.Data); err != nil {
		return centralRecord{}, fmt.Errorf("deflate %s: %w", entry.Name, err)
	}

	if err := deflater.Close(); err != nil {
		return centralRecord{}, fmt.Errorf("deflate %s: %w", entry.Name, err)
	}

	record := centralRecord{
		Name:         entry.Name,
		CRC:          crc32.ChecksumIEEE(entry.Data),
		Compressed:   uint32(compressed.Len()),
		Uncompressed: uint32(len(entry.Data)),
		Method:       8,
		LocalOffset:  uint32(offset),
	}

	header := make([]byte, 30)
	binary.LittleEndian.PutUint32(header[0:], 0x04034b50)
	binary.LittleEndian.PutUint16(header[4:], 20)
	binary.LittleEndian.PutUint16(header[6:], 0) // no data descriptor: sizes are known
	binary.LittleEndian.PutUint16(header[8:], record.Method)
	binary.LittleEndian.PutUint16(header[10:], record.ModifiedTime)
	binary.LittleEndian.PutUint16(header[12:], record.ModifiedDate)
	binary.LittleEndian.PutUint32(header[14:], record.CRC)
	binary.LittleEndian.PutUint32(header[18:], record.Compressed)
	binary.LittleEndian.PutUint32(header[22:], record.Uncompressed)
	binary.LittleEndian.PutUint16(header[26:], uint16(len(entry.Name)))
	binary.LittleEndian.PutUint16(header[28:], 0)

	writer.write(header)
	writer.write([]byte(entry.Name))
	writer.write(compressed.Bytes())

	return record, writer.err
}

func writeCentralRecord(writer *countingWriter, record centralRecord) error {
	header := make([]byte, 46)

	binary.LittleEndian.PutUint32(header[0:], 0x02014b50)
	binary.LittleEndian.PutUint16(header[4:], 20) // made by
	binary.LittleEndian.PutUint16(header[6:], 20) // needed
	binary.LittleEndian.PutUint16(header[8:], 0)
	binary.LittleEndian.PutUint16(header[10:], record.Method)
	binary.LittleEndian.PutUint16(header[12:], record.ModifiedTime)
	binary.LittleEndian.PutUint16(header[14:], record.ModifiedDate)
	binary.LittleEndian.PutUint32(header[16:], record.CRC)
	binary.LittleEndian.PutUint32(header[20:], record.Compressed)
	binary.LittleEndian.PutUint32(header[24:], record.Uncompressed)
	binary.LittleEndian.PutUint16(header[28:], uint16(len(record.Name)))
	binary.LittleEndian.PutUint16(header[30:], 0)
	binary.LittleEndian.PutUint16(header[32:], 0)
	binary.LittleEndian.PutUint16(header[34:], 0)
	binary.LittleEndian.PutUint16(header[36:], 0)
	binary.LittleEndian.PutUint32(header[38:], 0o100644<<16)
	binary.LittleEndian.PutUint32(header[42:], record.LocalOffset)

	writer.write(header)
	writer.write([]byte(record.Name))

	return writer.err
}

func writeDirectoryEnd(writer *countingWriter, count int, offset, size int64, comment []byte) error {
	header := make([]byte, 22)

	binary.LittleEndian.PutUint32(header[0:], 0x06054b50)
	binary.LittleEndian.PutUint16(header[8:], uint16(count))
	binary.LittleEndian.PutUint16(header[10:], uint16(count))
	binary.LittleEndian.PutUint32(header[12:], uint32(size))
	binary.LittleEndian.PutUint32(header[16:], uint32(offset))
	binary.LittleEndian.PutUint16(header[20:], uint16(len(comment)))

	writer.write(header)
	writer.write(comment)

	return writer.err
}

// countingWriter tracks the output offset, which the zip records refer to.
type countingWriter struct {
	target  io.Writer
	written int64
	err     error
}

func newWriter(target io.Writer) *countingWriter {
	return &countingWriter{target: target}
}

func (w *countingWriter) Write(p []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}

	written, err := w.target.Write(p)
	w.written += int64(written)
	w.err = err

	return written, err
}

func (w *countingWriter) write(p []byte) {
	if w.err != nil {
		return
	}

	_, _ = w.Write(p)
}

// zipExtra is kept for the entry list type used by the patch.
type zipExtra = extraEntry

var _ = zip.Store
