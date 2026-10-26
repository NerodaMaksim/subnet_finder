package main

import (
	"image"
	"image/color"
	"image/png"
	"math"
	"os"
)

func main() {
	path := "build/icon.png"
	if len(os.Args) > 1 {
		path = os.Args[1]
	}
	if err := os.MkdirAll("build", 0o755); err != nil && !os.IsExist(err) {
		panic(err)
	}

	const s = 1024
	img := image.NewRGBA(image.Rect(0, 0, s, s))
	bg := color.RGBA{15, 20, 25, 255}
	fill(img, bg)

	accent := color.RGBA{61, 156, 240, 255}
	dim := color.RGBA{42, 111, 168, 255}
	core := color.RGBA{94, 196, 138, 255}

	cx, cy := 512.0, 512.0
	nodes := [][2]float64{
		{cx, cy},
		{cx, cy - 250},
		{cx + 230, cy - 80},
		{cx + 140, cy + 220},
		{cx - 140, cy + 220},
		{cx - 230, cy - 80},
	}

	for i := 1; i < len(nodes); i++ {
		line(img, nodes[0][0], nodes[0][1], nodes[i][0], nodes[i][1], 18, dim)
	}
	line(img, nodes[1][0], nodes[1][1], nodes[2][0], nodes[2][1], 12, dim)
	line(img, nodes[2][0], nodes[2][1], nodes[3][0], nodes[3][1], 12, dim)
	line(img, nodes[3][0], nodes[3][1], nodes[4][0], nodes[4][1], 12, dim)
	line(img, nodes[4][0], nodes[4][1], nodes[5][0], nodes[5][1], 12, dim)
	line(img, nodes[5][0], nodes[5][1], nodes[1][0], nodes[1][1], 12, dim)

	for i, n := range nodes {
		r := 48.0
		col := accent
		if i == 0 {
			r = 72
			col = core
		}
		disk(img, n[0], n[1], r, col)
		disk(img, n[0], n[1], r*0.38, bg)
	}

	f, err := os.Create(path)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	if err := png.Encode(f, img); err != nil {
		panic(err)
	}
}

func fill(img *image.RGBA, c color.RGBA) {
	b := img.Bounds()
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			img.SetRGBA(x, y, c)
		}
	}
}

func disk(img *image.RGBA, cx, cy, r float64, c color.RGBA) {
	minX := int(math.Floor(cx - r - 1))
	maxX := int(math.Ceil(cx + r + 1))
	minY := int(math.Floor(cy - r - 1))
	maxY := int(math.Ceil(cy + r + 1))
	b := img.Bounds()
	for y := minY; y <= maxY; y++ {
		for x := minX; x <= maxX; x++ {
			if !image.Pt(x, y).In(b) {
				continue
			}
			d := math.Hypot(float64(x)-cx, float64(y)-cy)
			blend(img, x, y, c, cover(d, r))
		}
	}
}

func line(img *image.RGBA, x0, y0, x1, y1, width float64, c color.RGBA) {
	minX := int(math.Floor(math.Min(x0, x1) - width - 1))
	maxX := int(math.Ceil(math.Max(x0, x1) + width + 1))
	minY := int(math.Floor(math.Min(y0, y1) - width - 1))
	maxY := int(math.Ceil(math.Max(y0, y1) + width + 1))
	b := img.Bounds()
	for y := minY; y <= maxY; y++ {
		for x := minX; x <= maxX; x++ {
			if !image.Pt(x, y).In(b) {
				continue
			}
			d := distToSeg(float64(x), float64(y), x0, y0, x1, y1)
			blend(img, x, y, c, cover(d, width/2))
		}
	}
}

func distToSeg(px, py, x0, y0, x1, y1 float64) float64 {
	dx := x1 - x0
	dy := y1 - y0
	if dx == 0 && dy == 0 {
		return math.Hypot(px-x0, py-y0)
	}
	t := ((px-x0)*dx + (py-y0)*dy) / (dx*dx + dy*dy)
	t = math.Max(0, math.Min(1, t))
	return math.Hypot(px-(x0+t*dx), py-(y0+t*dy))
}

func cover(dist, radius float64) float64 {
	a := radius - dist + 0.5
	if a <= 0 {
		return 0
	}
	if a >= 1 {
		return 1
	}
	return a
}

func blend(img *image.RGBA, x, y int, c color.RGBA, a float64) {
	if a <= 0 {
		return
	}
	if a > 1 {
		a = 1
	}
	p := img.RGBAAt(x, y)
	ia := 1 - a
	img.SetRGBA(x, y, color.RGBA{
		R: uint8(float64(p.R)*ia + float64(c.R)*a),
		G: uint8(float64(p.G)*ia + float64(c.G)*a),
		B: uint8(float64(p.B)*ia + float64(c.B)*a),
		A: 255,
	})
}
