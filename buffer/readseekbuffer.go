package buffer

import (
	"errors"
	"io"
)

// A Buffer is a fix-sized buffer of bytes with Read and Write methods.
type ReadSeekBuffer struct {
	buf []byte // contents are the bytes buf[off : len(buf)]
	off int64  // read at &buf[off], write at &buf[len(buf)]
}

// NewReadSeekBuffer creates and initializes a new NewReadSeekBuffer using buf as its initial
// contents. It is intended to prepare a NewReadSeekBuffer to read existing data.
func NewReadSeekBuffer(buf []byte) *ReadSeekBuffer { return &ReadSeekBuffer{buf: buf, off: 0} }

// Read reads the next len(p) bytes from the buffer or until the buffer
// is drained. The return value n is the number of bytes read. If the
// buffer has no data to return, err is io.EOF (unless len(p) is zero);
// otherwise it is nil.
func (b *ReadSeekBuffer) Read(p []byte) (n int, err error) {
	if b.off >= int64(len(b.buf)) {
		if len(p) == 0 {
			return
		}
		return 0, io.EOF
	}
	n = copy(p, b.buf[b.off:])
	b.off += int64(n)
	return
}

// Seek sets the offset for the next Read on buffer to offset, interpreted
// according to whence: 0 means relative to the origin of the file, 1 means
// relative to the current offset, and 2 means relative to the end.
// It returns the new offset and an error, if any.
func (b *ReadSeekBuffer) Seek(offset int64, whence int) (ret int64, err error) {
	lenBuf := int64(len(b.buf))

	switch whence {
	case 0:
		b.off = 0
	case 1:
		b.off += offset
	case 2:
		b.off = lenBuf - offset
	default:
	}

	if b.off < 0 {
		b.off = 0
		return b.off, errors.New("Seek to minus offset")
	}

	if b.off > lenBuf {
		b.off = lenBuf
		return b.off, errors.New("Seek to over buffer length offset")
	}

	return b.off, nil
}
