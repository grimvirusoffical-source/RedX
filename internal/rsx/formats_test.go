package rsx

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"testing"
)

type fmtVec struct {
	Name      string      `json:"name"`
	Blob      string      `json:"blob_hex"`
	Expect    string      `json:"expect"`
	RC        json.Number `json:"librsx_rc"`
	Password  string      `json:"password"`
	Plain     string      `json:"plaintext_hex"`
	PtLen     json.Number `json:"plaintext_len"`
	ServerKey string      `json:"server_key_hex"`
	Data      string      `json:"data_hex"`
	ReqCaps   json.Number `json:"required_caps"`
	KXAI      string      `json:"kxai_hex"`
}

type fmtFile struct {
	Session struct {
		KXAI     string `json:"kxai_hex"`
		Password string `json:"password"`
	} `json:"session"`
	UserAAD string   `json:"user_aad"`
	Vectors []fmtVec `json:"vectors"`
	KXAIVec []fmtVec `json:"kxai_vectors"`
	Bands   []struct {
		Band     int    `json:"band"`
		Capacity uint64 `json:"capacity"`
		Total    uint64 `json:"total_size_aad0"`
	} `json:"bands"`
}

func rcOf(err error) int {
	var e Error
	if errors.As(err, &e) {
		return int(e)
	}
	return 0
}

func checkRC(t *testing.T, v fmtVec, err error) {
	t.Helper()
	want, _ := strconv.Atoi(v.RC.String())
	if err == nil || rcOf(err) != want {
		t.Fatalf("%s: got %v (rc %d), want rc %d", v.Name, err, rcOf(err), want)
	}
}

func vecSession(t *testing.T, f *fmtFile) *Session {
	kek, _, _, err := parseKXAI(unhex(t, f.Session.KXAI), []byte(f.Session.Password), nil)
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	s, err := NewSessionFromKey(kek[:])
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func rulePT(n int) []byte {
	p := make([]byte, n)
	for i := range p {
		p[i] = byte(i*31 + 7)
	}
	return p
}

func TestRSX1Vectors(t *testing.T) {
	var f fmtFile
	loadVec(t, "rsx1.json", &f)
	pw := "vector-password"
	for _, v := range f.Vectors {
		p := pw
		if v.Password != "" {
			p = v.Password
		}
		pt, err := Open1([]byte(p), unhex(t, v.Blob))
		if v.Expect == "OK" {
			if err != nil {
				t.Fatalf("%s: %v", v.Name, err)
			}
			eqHex(t, v.Name, pt, v.Plain)
		} else {
			checkRC(t, v, err)
		}
	}
}

func TestRSX2Vectors(t *testing.T) {
	var f fmtFile
	loadVec(t, "rsx2.json", &f)
	for _, v := range f.Vectors {
		p := "vector-password"
		if v.Password != "" {
			p = v.Password
		}
		pt, err := Open2([]byte(p), unhex(t, v.ServerKey), unhex(t, v.Blob))
		if v.Expect == "OK" {
			if err != nil {
				t.Fatalf("%s: %v", v.Name, err)
			}
			eqHex(t, v.Name, pt, v.Plain)
		} else {
			checkRC(t, v, err)
		}
	}
}

func TestRSX3Vectors(t *testing.T) {
	var f fmtFile
	loadVec(t, "rsx3.json", &f)
	s := vecSession(t, &f)
	defer s.Close()
	aad := []byte(f.UserAAD)
	for _, v := range f.Vectors {
		blob := unhex(t, v.Blob)
		pt, err := s.Open3(aad, blob)
		if v.Expect == "OK" {
			n, _ := strconv.Atoi(v.PtLen.String())
			if err != nil || !bytes.Equal(pt, rulePT(n)) {
				t.Fatalf("%s: %v", v.Name, err)
			}
			// streaming reader with tiny reads must agree
			r, err := s.NewDecryptReader(bytes.NewReader(blob), aad)
			if err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(io.LimitReader(r, 1<<30))
			if err != nil || !bytes.Equal(got, pt) {
				t.Fatalf("%s stream: %v", v.Name, err)
			}
			if _, err := s.Open3([]byte("other"), blob); rcOf(err) != -2 {
				t.Fatalf("%s wrong aad: %v", v.Name, err)
			}
		} else {
			checkRC(t, v, err)
		}
	}
	for _, v := range f.KXAIVec {
		_, _, _, err := parseKXAI(unhex(t, v.KXAI), []byte(v.Password), nil)
		if v.Expect == "OK" {
			if err != nil {
				t.Fatal(v.Name, err)
			}
		} else {
			checkRC(t, v, err)
		}
	}
	// Go-sealed streams open, and sizes match the C++ size function.
	for _, n := range []int{0, 1, 65535, 65536, 65537, 140000} {
		b, err := s.Seal3(aad, rulePT(n))
		if err != nil {
			t.Fatal(err)
		}
		if uint64(len(b)) != rsx3Size(uint64(n), uint64(len(aad))) {
			t.Fatalf("size %d: %d", n, len(b))
		}
		pt, err := s.Open3(aad, b)
		if err != nil || !bytes.Equal(pt, rulePT(n)) {
			t.Fatalf("rt %d: %v", n, err)
		}
		if _, err := s.Open3(aad, append(b, 0)); rcOf(err) != -2 {
			t.Fatalf("trailing: %v", err)
		}
		if _, err := s.Open3(aad, b[:len(b)-1]); err == nil {
			t.Fatal("truncated accepted")
		}
	}
}

func TestRSXCVectors(t *testing.T) {
	var f fmtFile
	loadVec(t, "rsxc.json", &f)
	s := vecSession(t, &f)
	defer s.Close()
	aad := []byte(f.UserAAD)
	for _, b := range f.Bands {
		if BandCapacity(b.Band) != b.Capacity || BandTotalSize(b.Band, 0) != b.Total {
			t.Fatalf("band %d", b.Band)
		}
	}
	for _, v := range f.Vectors {
		rq, _ := strconv.Atoi(v.ReqCaps.String())
		pt, _, err := s.OpenC(aad, unhex(t, v.Blob), uint32(rq))
		if v.Expect == "OK" {
			if err != nil {
				t.Fatalf("%s: %v", v.Name, err)
			}
			eqHex(t, v.Name, pt, v.Data)
		} else {
			checkRC(t, v, err)
		}
	}
	for _, band := range []int{0, 1, BandAuto, BandNone} {
		d := []byte("container data")
		b, err := s.SealC(aad, d, band)
		if err != nil {
			t.Fatal(err)
		}
		if band >= 0 && uint64(len(b)) != BandTotalSize(band, len(aad)) {
			t.Fatal("band size")
		}
		got, _, err := s.OpenC(aad, b, 0)
		if err != nil || !bytes.Equal(got, d) {
			t.Fatal(err)
		}
	}
}

func TestOuterDuressRatchetShamir(t *testing.T) {
	s, _ := NewSessionFromKey(bytes.Repeat([]byte{7}, 32))
	in := rulePT(203)
	o, err := s.OuterWrap(in)
	if err != nil {
		t.Fatal(err)
	}
	back, err := s.OuterUnwrap(o)
	if err != nil || !bytes.Equal(back, in) {
		t.Fatal("outer")
	}
	kp := KDFParams{T: 1, M: 32, P: 1}
	blob, err := DuressSeal([][]byte{[]byte("real"), []byte("decoy")}, [][]byte{[]byte("A"), []byte("BB")}, 2, 0, kp)
	if err != nil || uint64(len(blob)) != DuressSize(0, 2) {
		t.Fatal(err)
	}
	for pw, want := range map[string]string{"real": "A", "decoy": "BB"} {
		got, err := DuressOpen([]byte(pw), blob, 2, kp)
		if err != nil || string(got) != want {
			t.Fatal(pw, err)
		}
	}
	if _, err := DuressOpen([]byte("nope"), blob, 2, kp); rcOf(err) != -1 {
		t.Fatal(err)
	}
	m := bytes.Repeat([]byte{1}, 32)
	a, _ := NewRatchet(m, nil)
	b, _ := NewRatchet(m, nil)
	for i := 0; i < 3; i++ {
		c, _ := a.Seal([]byte("x"), []byte{byte(i)})
		bad := append([]byte(nil), c...)
		bad[len(bad)-1] ^= 1
		if _, err := b.Open([]byte("x"), bad); rcOf(err) != -1 {
			t.Fatal("forged")
		}
		p, err := b.Open([]byte("x"), c)
		if err != nil || p[0] != byte(i) {
			t.Fatal(err)
		}
		if _, err := b.Open([]byte("x"), c); rcOf(err) != -2 {
			t.Fatal("replay")
		}
	}
	sec := rulePT(32)
	sh, err := ShamirSplit(sec, 3, 5)
	if err != nil || len(sh[0]) != 65 {
		t.Fatal(err)
	}
	got, err := ShamirCombine([][]byte{sh[4], sh[1], sh[2]})
	if err != nil || !bytes.Equal(got, sec) {
		t.Fatal(err)
	}
	if _, err := ShamirCombine(sh[:2]); rcOf(err) != -6 {
		t.Fatal(err)
	}
	sh[1][20] ^= 1
	if _, err := ShamirCombine(sh[:3]); rcOf(err) != -1 {
		t.Fatal(err)
	}
}
