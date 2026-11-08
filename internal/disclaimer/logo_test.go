package disclaimer

import (
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"testing"
)

func TestFitSize(t *testing.T) {
	cases := []struct {
		w, h, maxW, maxH int
		scale            float64
		wantW, wantH     int
	}{
		{1080, 160, 540, 80, 1, 540, 80},  // wide logo: fits the box
		{200, 200, 540, 80, 1, 80, 80},    // square logo: height bound
		{100, 20, 540, 80, 1, 100, 20},    // small logo: never enlarged at 100%
		{100, 20, 810, 120, 1.5, 150, 30}, // 150% display: enlarged by the display scale only
		{4000, 100, 540, 80, 1, 540, 14},  // very wide logo
		{0, 10, 540, 80, 1, 0, 0},         // invalid
	}
	for _, c := range cases {
		w, h := fitSize(c.w, c.h, c.maxW, c.maxH, c.scale)
		if w != c.wantW || h != c.wantH {
			t.Errorf("fitSize(%d,%d in %dx%d @%.1f) = %dx%d, want %dx%d", c.w, c.h, c.maxW, c.maxH, c.scale, w, h, c.wantW, c.wantH)
		}
	}
}

func TestFlattenComposite(t *testing.T) {
	// Left half opaque red, right half transparent.
	src := image.NewNRGBA(image.Rect(0, 0, 400, 100))
	for y := 0; y < 100; y++ {
		for x := 0; x < 200; x++ {
			src.SetNRGBA(x, y, color.NRGBA{R: 255, A: 255})
		}
	}
	white := color.NRGBA{R: 255, G: 255, B: 255, A: 255}
	out := flatten(src, 200, 50, white)
	if b := out.Bounds(); b.Dx() != 200 || b.Dy() != 50 {
		t.Fatalf("size %v", b)
	}
	if c := out.NRGBAAt(20, 20); c.R != 255 || c.G != 0 || c.B != 0 {
		t.Errorf("opaque area: %v, want red", c)
	}
	if c := out.NRGBAAt(180, 20); c != white {
		t.Errorf("transparent area: %v, want the background", c)
	}
	// Upscaling path keeps the size and stays opaque.
	up := flatten(src, 800, 200, white)
	if c := up.NRGBAAt(10, 10); c.A != 255 || c.R != 255 {
		t.Errorf("upscaled pixel: %v", c)
	}
}

func TestLogoBitmap(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "logo.png")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	img := image.NewNRGBA(image.Rect(0, 0, 300, 60))
	if err := png.Encode(f, img); err != nil {
		t.Fatal(err)
	}
	f.Close()
	hbm, w, h, err := logoBitmap(p, 540, 80, 1, color.NRGBA{R: 255, G: 255, B: 255, A: 255})
	if err != nil || hbm == 0 {
		t.Fatalf("logoBitmap: %v", err)
	}
	defer procDeleteObject.Call(hbm)
	if w != 300 || h != 60 {
		t.Errorf("size %dx%d", w, h)
	}
	if _, _, _, err := logoBitmap(filepath.Join(dir, "missing.png"), 540, 80, 1, color.NRGBA{}); err == nil {
		t.Error("a missing logo must fail")
	}
}
