package main

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"image/png"
	"math"
)

// iconPNG draws the app icon: an up and a down arrow on a blue tile. The
// rounded version has transparent corners; phones want the full square and
// round it themselves.
func iconPNG(size int, rounded bool) []byte {
	const ss = 3 // supersampling per axis
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	for py := range size {
		for px := range size {
			var bg, fg int
			for sy := range ss {
				for sx := range ss {
					x := (float64(px) + (float64(sx)+0.5)/ss) / float64(size)
					y := (float64(py) + (float64(sy)+0.5)/ss) / float64(size)
					if rounded && !inRoundedSquare(x, y, 0.22) {
						continue
					}
					bg++
					if inArrow(x-0.36, y) || inArrow(x-0.64, 1-y) {
						fg++
					}
				}
			}
			mix := func(a, b uint8) uint8 {
				if bg == 0 {
					return 0
				}
				return uint8((int(a)*(bg-fg) + int(b)*fg) / bg)
			}
			img.SetNRGBA(px, py, color.NRGBA{mix(0x24, 0xff), mix(0x56, 0xff), mix(0xd6, 0xff), uint8(255 * bg / (ss * ss))})
		}
	}
	var buf bytes.Buffer
	png.Encode(&buf, img)
	return buf.Bytes()
}

func inRoundedSquare(x, y, r float64) bool {
	dx := math.Max(math.Max(r-x, x-(1-r)), 0)
	dy := math.Max(math.Max(r-y, y-(1-r)), 0)
	return dx*dx+dy*dy <= r*r
}

// inArrow reports whether (dx, y) is inside an upward arrow centred on dx=0.
func inArrow(dx, y float64) bool {
	dx = math.Abs(dx)
	if y >= 0.24 && y <= 0.44 && dx <= 0.14*(y-0.24)/0.20 {
		return true // head
	}
	return y > 0.44 && y <= 0.76 && dx <= 0.045 // shaft
}

// iconICO packs the icon at several sizes into a Windows .ico, for the tray
// and shortcuts.
func iconICO() []byte {
	sizes := []int{16, 24, 32, 48, 256}
	imgs := make([][]byte, len(sizes))
	for i, s := range sizes {
		imgs[i] = iconPNG(s, true)
	}
	var buf bytes.Buffer
	binary.Write(&buf, binary.LittleEndian, []uint16{0, 1, uint16(len(sizes))}) // reserved, type icon, count
	offset := 6 + 16*len(sizes)
	for i, s := range sizes {
		buf.Write([]byte{byte(s % 256), byte(s % 256), 0, 0}) // 256 is written as 0
		binary.Write(&buf, binary.LittleEndian, []uint16{1, 32})
		binary.Write(&buf, binary.LittleEndian, []uint32{uint32(len(imgs[i])), uint32(offset)})
		offset += len(imgs[i])
	}
	for _, img := range imgs {
		buf.Write(img)
	}
	return buf.Bytes()
}
