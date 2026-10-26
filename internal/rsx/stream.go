package rsx

import (
	"bufio"
	"io"
	"os"
)

// RSX3 format v2 (ver byte 4). Layout (see docs/spec/containers.md):
//
//	"RSX3" | hdr_body{ver=4, flags=1, wrap_nonce12, wdek_ct32, wdek_tag16, aad_len2, aad}
//	| prefix8 | header_tag16 | chunks{len3, ct, tag16}*
//
// hk = HKDF(DEK, prefix, "RSX3v2 hdr"), ck = HKDF(DEK, prefix, "RSX3v2 chunk")
// header_tag = AEAD(hk, 0^12, aad=hdr_body, "")
// chunk nonce = prefix || be32((ctr & 0x7fffffff) | last<<31), key ck, aad = header_tag || last
const rsx3Ver = 4

func buildHdrBody(wrapNonce, wct, wtag, aad []byte) []byte {
	h := make([]byte, 0, 64+len(aad))
	h = append(h, rsx3Ver, 1)
	h = append(h, wrapNonce...)
	h = append(h, wct...)
	h = append(h, wtag...)
	h = append(h, byte(len(aad)>>8), byte(len(aad)))
	return append(h, aad...)
}

func deriveSubkeys(dek, prefix []byte) (hk, ck [32]byte) {
	return hkdf32(dek, prefix, "RSX3v2 hdr"), hkdf32(dek, prefix, "RSX3v2 chunk")
}

func chunkNonce(prefix []byte, ctr uint32, last bool) []byte {
	n := make([]byte, 12)
	copy(n, prefix)
	c := ctr & 0x7fffffff
	if last {
		c |= 0x80000000
	}
	be32(n[8:], c)
	return n
}

// StreamWriter encrypts an RSX3 stream. Close writes the authenticated final chunk;
// a stream that is not closed is not decryptable (truncation is detected).
type StreamWriter struct {
	w       io.Writer
	ck      [32]byte
	prefix  [8]byte
	htag    [16]byte
	buf     []byte
	counter uint32
	alive   bool
	err     error
}

// NewEncryptWriter starts an RSX3 stream to w under a fresh random DEK wrapped by the session KEK.
func (s *Session) NewEncryptWriter(w io.Writer, aad []byte) (*StreamWriter, error) {
	if err := s.ok(); err != nil {
		return nil, err
	}
	if len(aad) > MaxAADLen {
		return nil, ErrParam
	}
	dek := make([]byte, 32)
	defer Wipe(dek)
	wn := make([]byte, 12)
	if Random(dek) != nil || Random(wn) != nil {
		return nil, ErrRNG
	}
	wct, wtag, _ := AeadEncrypt(s.kek[:], wn, []byte("RSX3DEK"), dek)
	hdr := buildHdrBody(wn, wct, wtag[:], aad)
	return newStreamWriter(w, dek, hdr)
}

func newStreamWriter(w io.Writer, dek, hdr []byte) (*StreamWriter, error) {
	st := &StreamWriter{w: w, buf: make([]byte, 0, ChunkSize)}
	if Random(st.prefix[:]) != nil {
		return nil, ErrRNG
	}
	hk, ck := deriveSubkeys(dek, st.prefix[:])
	st.ck = ck
	_, st.htag, _ = AeadEncrypt(hk[:], make([]byte, 12), hdr, nil)
	Wipe(hk[:])
	out := make([]byte, 0, 4+len(hdr)+24)
	out = append(out, "RSX3"...)
	out = append(out, hdr...)
	out = append(out, st.prefix[:]...)
	out = append(out, st.htag[:]...)
	if _, err := w.Write(out); err != nil {
		return nil, ErrIO
	}
	st.alive = true
	return st, nil
}

func (st *StreamWriter) writeChunk(last bool) error {
	aad := append(st.htag[:16:16], 0)
	if last {
		aad[16] = 1
	}
	ct, tag, _ := AeadEncrypt(st.ck[:], chunkNonce(st.prefix[:], st.counter, last), aad, st.buf)
	var l [3]byte
	be24(l[:], uint32(len(st.buf)))
	rec := make([]byte, 0, 3+len(ct)+16)
	rec = append(rec, l[:]...)
	rec = append(rec, ct...)
	rec = append(rec, tag[:]...)
	_, err := st.w.Write(rec)
	Wipe(ct)
	if err != nil {
		return ErrIO
	}
	return nil
}

// Write encrypts p (buffered into 64 KiB chunks).
func (st *StreamWriter) Write(p []byte) (int, error) {
	if !st.alive {
		return 0, ErrInternal
	}
	if st.err != nil {
		return 0, st.err
	}
	n := len(p)
	for len(p) > 0 {
		k := ChunkSize - len(st.buf)
		if k > len(p) {
			k = len(p)
		}
		st.buf = append(st.buf, p[:k]...)
		p = p[k:]
		if len(st.buf) == ChunkSize {
			if err := st.writeChunk(false); err != nil {
				st.err = err
				return n - len(p), err
			}
			Wipe(st.buf)
			st.buf = st.buf[:0]
			st.counter++
			if st.counter >= MaxChunks {
				st.err = ErrLimit
				return n - len(p), ErrLimit
			}
		}
	}
	return n, nil
}

// Close writes the final chunk. It does not close the underlying writer.
func (st *StreamWriter) Close() error {
	if !st.alive {
		return ErrInternal
	}
	st.alive = false
	defer func() { Wipe(st.ck[:]); Wipe(st.buf[:cap(st.buf)]) }()
	if st.err != nil {
		return st.err
	}
	return st.writeChunk(true)
}

// StreamReader decrypts an RSX3 stream. Read returns io.EOF only after the final chunk
// verified and the input ended cleanly; any truncation, reordering or trailing byte is an error.
type StreamReader struct {
	r       *bufio.Reader
	ck      [32]byte
	prefix  [8]byte
	htag    [16]byte
	pt      []byte
	off     int
	counter uint32
	final   bool
	err     error
}

// NewDecryptReader parses the RSX3 header from r. aad must equal the stored AAD exactly.
func (s *Session) NewDecryptReader(r io.Reader, aad []byte) (*StreamReader, error) {
	if err := s.ok(); err != nil {
		return nil, err
	}
	br := bufio.NewReaderSize(r, ChunkSize+64)
	h := make([]byte, 4+2+12+32+16+2)
	if _, err := io.ReadFull(br, h); err != nil || string(h[:4]) != "RSX3" {
		return nil, ErrFormat
	}
	if h[4] != rsx3Ver || h[5]&1 == 0 {
		return nil, ErrFormat
	}
	al := int(rd16(h[66:]))
	stored := make([]byte, al)
	if _, err := io.ReadFull(br, stored); err != nil {
		return nil, ErrFormat
	}
	if len(aad) != al || !CtEq(stored, aad) {
		return nil, ErrFormat
	}
	dek, err := AeadDecrypt(s.kek[:], h[6:18], []byte("RSX3DEK"), h[18:50], h[50:66])
	if err != nil {
		return nil, ErrAuth
	}
	defer Wipe(dek)
	hdr := buildHdrBody(h[6:18], h[18:50], h[50:66], stored)
	return newStreamReader(br, dek, hdr)
}

func newStreamReader(br *bufio.Reader, dek, hdr []byte) (*StreamReader, error) {
	st := &StreamReader{r: br}
	if _, err := io.ReadFull(br, st.prefix[:]); err != nil {
		return nil, ErrFormat
	}
	if _, err := io.ReadFull(br, st.htag[:]); err != nil {
		return nil, ErrFormat
	}
	hk, ck := deriveSubkeys(dek, st.prefix[:])
	_, exp, _ := AeadEncrypt(hk[:], make([]byte, 12), hdr, nil)
	Wipe(hk[:])
	if !CtEq(exp[:], st.htag[:]) {
		Wipe(ck[:])
		return nil, ErrAuth
	}
	st.ck = ck
	return st, nil
}

func (st *StreamReader) more() bool {
	_, err := st.r.Peek(1)
	return err == nil
}

func (st *StreamReader) fail(e error) error {
	st.err = e
	Wipe(st.ck[:])
	Wipe(st.pt)
	return e
}

func (st *StreamReader) next() error {
	if st.counter >= MaxChunks {
		return st.fail(ErrLimit)
	}
	if !st.more() {
		return st.fail(ErrFormat) // missing final chunk
	}
	var l [3]byte
	if _, err := io.ReadFull(st.r, l[:]); err != nil {
		return st.fail(ErrFormat)
	}
	n := int(rd24(l[:]))
	if n > ChunkSize {
		return st.fail(ErrFormat)
	}
	ct := make([]byte, n+16)
	if _, err := io.ReadFull(st.r, ct); err != nil {
		return st.fail(ErrFormat)
	}
	more := st.more()
	last := !more
	try := func(last bool) ([]byte, error) {
		aad := append(st.htag[:16:16], 0)
		if last {
			aad[16] = 1
		}
		return AeadDecrypt(st.ck[:], chunkNonce(st.prefix[:], st.counter, last), aad, ct[:n], ct[n:])
	}
	pt, err := try(last)
	if err != nil {
		alt := !last
		pt, err = try(alt)
		if err != nil {
			return st.fail(ErrAuth)
		}
		if alt && more {
			Wipe(pt)
			return st.fail(ErrFormat) // final chunk followed by trailing bytes
		}
		last = alt
	}
	if last {
		if more {
			Wipe(pt)
			return st.fail(ErrFormat)
		}
		st.final = true
	}
	st.pt, st.off = pt, 0
	st.counter++
	return nil
}

// Read implements io.Reader.
func (st *StreamReader) Read(p []byte) (int, error) {
	for {
		if st.err != nil {
			return 0, st.err
		}
		if st.off < len(st.pt) {
			n := copy(p, st.pt[st.off:])
			st.off += n
			if st.off == len(st.pt) {
				Wipe(st.pt)
				st.pt, st.off = nil, 0
			}
			return n, nil
		}
		if st.final {
			if st.more() {
				return 0, st.fail(ErrFormat)
			}
			Wipe(st.ck[:])
			return 0, io.EOF
		}
		if err := st.next(); err != nil {
			return 0, err
		}
	}
}

// Seal3 is in-memory RSX3 (rsx_seal3).
func (s *Session) Seal3(aad, pt []byte) ([]byte, error) {
	if err := s.ok(); err != nil {
		return nil, err
	}
	if uint64(len(pt)) > MaxBlob {
		return nil, ErrLimit
	}
	var buf bytesBuffer
	w, err := s.NewEncryptWriter(&buf, aad)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(pt); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.b, nil
}

// Open3 is in-memory RSX3 open (rsx_open3).
func (s *Session) Open3(aad, blob []byte) ([]byte, error) {
	if err := s.ok(); err != nil {
		return nil, err
	}
	if uint64(len(blob)) > MaxBlob {
		return nil, ErrLimit
	}
	if len(blob) < 4+2+12+32+16+2+8+16 || string(blob[:4]) != "RSX3" {
		return nil, ErrFormat
	}
	r, err := s.NewDecryptReader(&bytesReader{b: blob}, aad)
	if err != nil {
		return nil, err
	}
	out, err := io.ReadAll(r)
	if err != nil {
		Wipe(out)
		return nil, err
	}
	return out, nil
}

type bytesBuffer struct{ b []byte }

func (w *bytesBuffer) Write(p []byte) (int, error) { w.b = append(w.b, p...); return len(p), nil }

type bytesReader struct {
	b   []byte
	off int
}

func (r *bytesReader) Read(p []byte) (int, error) {
	if r.off >= len(r.b) {
		return 0, io.EOF
	}
	n := copy(p, r.b[r.off:])
	r.off += n
	return n, nil
}

// EncryptFile is rsx_encrypt_file: out is written to out.partial and published without replacing.
func (s *Session) EncryptFile(inPath, outPath string, aad []byte, cancel *int32) error {
	if err := s.ok(); err != nil {
		return err
	}
	in, err := os.Open(inPath)
	if err != nil {
		return ErrIO
	}
	defer in.Close()
	ao, err := atomicOpen(outPath)
	if err != nil {
		return err
	}
	w, err := s.NewEncryptWriter(ao, aad)
	if err != nil {
		ao.abort()
		return err
	}
	if err := copyCancel(w, in, cancel); err != nil {
		ao.abort()
		return err
	}
	if err := w.Close(); err != nil {
		ao.abort()
		return err
	}
	return ao.commit()
}

// DecryptFile is rsx_decrypt_file: plaintext is published only after full authentication.
func (s *Session) DecryptFile(inPath, outPath string, aad []byte, cancel *int32) error {
	if err := s.ok(); err != nil {
		return err
	}
	in, err := os.Open(inPath)
	if err != nil {
		return ErrIO
	}
	defer in.Close()
	r, err := s.NewDecryptReader(in, aad)
	if err != nil {
		return err
	}
	ao, err := atomicOpen(outPath)
	if err != nil {
		return err
	}
	if err := copyCancel(ao, r, cancel); err != nil {
		ao.abort()
		return err
	}
	return ao.commit()
}

func copyCancel(w io.Writer, r io.Reader, cancel *int32) error {
	buf := make([]byte, ChunkSize)
	defer Wipe(buf)
	for {
		if cancel != nil && loadCancel(cancel) {
			return ErrCancelled
		}
		n, err := r.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				if e, ok := werr.(Error); ok {
					return e
				}
				return ErrIO
			}
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			if e, ok := err.(Error); ok {
				return e
			}
			return ErrIO
		}
	}
}
