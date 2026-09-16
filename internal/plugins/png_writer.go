package plugins

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"os"
)

// writeBGRAAsPNG converts a raw BGRA buffer to a minimal PNG (no
// external deps: hand-rolled IHDR/IDAT with zlib). Used by the
// screenshot plugin so the implant needs no image library.
func writeBGRAAsPNG(path string, bgra []byte, w, h int) error {
	if w <= 0 || h <= 0 || len(bgra) < w*h*4 {
		return os.ErrInvalid
	}
	// PNG: RGBA rows with a filter byte (0 = none) per row
	raw := make([]byte, 0, h*(1+w*4))
	for y := 0; y < h; y++ {
		raw = append(raw, 0)
		row := bgra[y*w*4 : (y+1)*w*4]
		for x := 0; x < w; x++ {
			b, g, r, a := row[x*4], row[x*4+1], row[x*4+2], row[x*4+3]
			raw = append(raw, r, g, b, a)
		}
	}

	var idat bytes.Buffer
	zw := zlib.NewWriter(&idat)
	zw.Write(raw)
	zw.Close()

	var png bytes.Buffer
	png.Write([]byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A})
	writeChunk(&png, "IHDR", func(b *bytes.Buffer) {
		binary.Write(b, binary.BigEndian, uint32(w))
		binary.Write(b, binary.BigEndian, uint32(h))
		b.WriteByte(8) // bit depth
		b.WriteByte(6) // color type RGBA
		b.WriteByte(0) // compression
		b.WriteByte(0) // filter
		b.WriteByte(0) // interlace
	})
	writeChunk(&png, "IDAT", func(b *bytes.Buffer) { b.Write(idat.Bytes()) })
	writeChunk(&png, "IEND", func(b *bytes.Buffer) {})
	return os.WriteFile(path, png.Bytes(), 0o600)
}

func writeChunk(out *bytes.Buffer, typ string, fill func(*bytes.Buffer)) {
	var body bytes.Buffer
	fill(&body)
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(body.Len()))
	out.Write(lenBuf[:])
	out.WriteString(typ)
	out.Write(body.Bytes())
	crc := crc32Bytes(append([]byte(typ), body.Bytes()...))
	var crcBuf [4]byte
	binary.BigEndian.PutUint32(crcBuf[:], crc)
	out.Write(crcBuf[:])
}

func crc32Bytes(data []byte) uint32 {
	var table [256]uint32
	for i := 0; i < 256; i++ {
		c := uint32(i)
		for k := 0; k < 8; k++ {
			if c&1 == 1 {
				c = 0xEDB88320 ^ (c >> 1)
			} else {
				c >>= 1
			}
		}
		table[i] = c
	}
	crc := uint32(0xFFFFFFFF)
	for _, b := range data {
		crc = table[(crc^uint32(b))&0xFF] ^ (crc >> 8)
	}
	return crc ^ 0xFFFFFFFF
}
