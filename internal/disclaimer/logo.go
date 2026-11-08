package disclaimer

import (
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	_ "image/jpeg" // logo formats
	_ "image/png"
	"io"
	"math"
	"os"
	"unsafe"
)

const (
	maxLogoFileBytes = 5 << 20
	maxLogoPixels    = 4096
)

// loadLogo decodes a PNG or JPEG logo.
func loadLogo(path string) (image.Image, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	cfg, _, err := image.DecodeConfig(io.LimitReader(f, maxLogoFileBytes))
	if err != nil {
		return nil, fmt.Errorf("logo %s: %w", path, err)
	}
	if cfg.Width <= 0 || cfg.Height <= 0 || cfg.Width > maxLogoPixels || cfg.Height > maxLogoPixels {
		return nil, fmt.Errorf("logo %s: %dx%d pixels, at most %dx%d", path, cfg.Width, cfg.Height, maxLogoPixels, maxLogoPixels)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	img, _, err := image.Decode(io.LimitReader(f, maxLogoFileBytes))
	if err != nil {
		return nil, fmt.Errorf("logo %s: %w", path, err)
	}
	return img, nil
}

// fitSize scales w x h to fit in maxW x maxH, never enlarging beyond
// maxScale (the display scale factor), and keeps the aspect ratio.
func fitSize(w, h, maxW, maxH int, maxScale float64) (int, int) {
	if w <= 0 || h <= 0 || maxW <= 0 || maxH <= 0 {
		return 0, 0
	}
	scale := math.Min(float64(maxW)/float64(w), float64(maxH)/float64(h))
	if maxScale > 0 && scale > maxScale {
		scale = maxScale
	}
	tw := int(math.Round(float64(w) * scale))
	th := int(math.Round(float64(h) * scale))
	return max(tw, 1), max(th, 1)
}

// flatten resizes the logo to tw x th and composites it over bg, so that
// transparent areas take the window background. Downscaling averages a grid
// of samples per target pixel; upscaling interpolates bilinearly.
func flatten(src image.Image, tw, th int, bg color.NRGBA) *image.NRGBA {
	b := src.Bounds()
	n := image.NewNRGBA(image.Rect(0, 0, b.Dx(), b.Dy()))
	draw.Draw(n, n.Bounds(), src, b.Min, draw.Src)
	sw, sh := b.Dx(), b.Dy()
	out := image.NewNRGBA(image.Rect(0, 0, tw, th))

	sx := float64(sw) / float64(tw)
	sy := float64(sh) / float64(th)
	gx := max(int(math.Ceil(sx)), 1)
	gy := max(int(math.Ceil(sy)), 1)

	pixel := func(x, y int) (r, g, bl, a float64) {
		x = min(max(x, 0), sw-1)
		y = min(max(y, 0), sh-1)
		i := n.PixOffset(x, y)
		p := n.Pix[i : i+4]
		a = float64(p[3]) / 255
		return float64(p[0]) * a, float64(p[1]) * a, float64(p[2]) * a, a // premultiplied
	}

	for ty := 0; ty < th; ty++ {
		for tx := 0; tx < tw; tx++ {
			var r, g, bl, a float64
			if sx <= 1 && sy <= 1 {
				// Bilinear interpolation for upscaling.
				fx := (float64(tx)+0.5)*sx - 0.5
				fy := (float64(ty)+0.5)*sy - 0.5
				x0, y0 := int(math.Floor(fx)), int(math.Floor(fy))
				dx, dy := fx-float64(x0), fy-float64(y0)
				for _, c := range [4]struct {
					x, y int
					w    float64
				}{{x0, y0, (1 - dx) * (1 - dy)}, {x0 + 1, y0, dx * (1 - dy)}, {x0, y0 + 1, (1 - dx) * dy}, {x0 + 1, y0 + 1, dx * dy}} {
					pr, pg, pb, pa := pixel(c.x, c.y)
					r, g, bl, a = r+pr*c.w, g+pg*c.w, bl+pb*c.w, a+pa*c.w
				}
			} else {
				// Box filter: average a gx x gy grid inside the source area.
				for j := 0; j < gy; j++ {
					y := int((float64(ty) + (float64(j)+0.5)/float64(gy)) * sy)
					for i := 0; i < gx; i++ {
						x := int((float64(tx) + (float64(i)+0.5)/float64(gx)) * sx)
						pr, pg, pb, pa := pixel(x, y)
						r, g, bl, a = r+pr, g+pg, bl+pb, a+pa
					}
				}
				k := float64(gx * gy)
				r, g, bl, a = r/k, g/k, bl/k, a/k
			}
			// Composite the premultiplied color over the background.
			o := out.PixOffset(tx, ty)
			out.Pix[o+0] = clamp8(r + float64(bg.R)*(1-a))
			out.Pix[o+1] = clamp8(g + float64(bg.G)*(1-a))
			out.Pix[o+2] = clamp8(bl + float64(bg.B)*(1-a))
			out.Pix[o+3] = 255
		}
	}
	return out
}

func clamp8(v float64) uint8 {
	switch {
	case v <= 0:
		return 0
	case v >= 255:
		return 255
	default:
		return uint8(v + 0.5)
	}
}

type bitmapInfoHeader struct {
	Size          uint32
	Width         int32
	Height        int32
	Planes        uint16
	BitCount      uint16
	Compression   uint32
	SizeImage     uint32
	XPelsPerMeter int32
	YPelsPerMeter int32
	ClrUsed       uint32
	ClrImportant  uint32
}

var procCreateDIBSection = modGdi32.NewProc("CreateDIBSection")

// toBitmap copies an opaque NRGBA image into a 32-bit top-down GDI bitmap.
func toBitmap(img *image.NRGBA) (uintptr, error) {
	w, h := img.Bounds().Dx(), img.Bounds().Dy()
	bi := struct {
		Header bitmapInfoHeader
		Colors [1]uint32
	}{Header: bitmapInfoHeader{Width: int32(w), Height: -int32(h), Planes: 1, BitCount: 32}}
	bi.Header.Size = uint32(unsafe.Sizeof(bi.Header))
	var bits uintptr
	hbm, _, err := procCreateDIBSection.Call(0, uintptr(unsafe.Pointer(&bi)), 0, uintptr(unsafe.Pointer(&bits)), 0, 0)
	if hbm == 0 || bits == 0 {
		return 0, fmt.Errorf("CreateDIBSection: %v", err)
	}
	dst := unsafe.Slice((*byte)(ptrFrom(bits)), w*h*4)
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			s := img.PixOffset(x, y)
			d := (y*w + x) * 4
			dst[d+0] = img.Pix[s+2] // B
			dst[d+1] = img.Pix[s+1] // G
			dst[d+2] = img.Pix[s+0] // R
			dst[d+3] = 255
		}
	}
	return hbm, nil
}

// logoBitmap loads, fits and flattens the logo into a GDI bitmap.
func logoBitmap(path string, maxW, maxH int, scale float64, bg color.NRGBA) (uintptr, int, int, error) {
	if path == "" {
		return 0, 0, 0, errors.New("no logo")
	}
	img, err := loadLogo(path)
	if err != nil {
		return 0, 0, 0, err
	}
	tw, th := fitSize(img.Bounds().Dx(), img.Bounds().Dy(), maxW, maxH, scale)
	hbm, err := toBitmap(flatten(img, tw, th, bg))
	return hbm, tw, th, err
}

// ptrFrom converts an address returned by Windows into a pointer.
func ptrFrom(u uintptr) unsafe.Pointer { return *(*unsafe.Pointer)(unsafe.Pointer(&u)) }
