package client

import (
	qrcode "github.com/skip2/go-qrcode"
)

// qrLevel is ECC L: the config carries keys (~300+ bytes) and a screen is not
// paper, so low recovery keeps the code compact enough for a phone (spec §6).
const qrLevel = qrcode.Low

// RenderTerminalQR renders the config as a half-block ("▀▄") QR for the
// terminal — half the height of full blocks, so it fits a phone screen. A quiet
// zone (border) is kept; scanners need it. invert flips dark/light for the
// common light-on-dark terminal (spec §6).
func RenderTerminalQR(content string, invert bool) (string, error) {
	q, err := qrcode.New(content, qrLevel)
	if err != nil {
		return "", err
	}
	q.DisableBorder = false // keep the quiet zone
	return q.ToSmallString(invert), nil
}

// WriteQRPNG writes the config as a PNG using the same library and ECC level
// (spec §6).
func WriteQRPNG(content, path string, size int) error {
	return qrcode.WriteFile(content, qrLevel, size, path)
}
