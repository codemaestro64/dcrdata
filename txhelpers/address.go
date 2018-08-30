package txhelpers

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"regexp"
	"strings"

	"github.com/decred/dcrd/chaincfg"
)

// DetectAddressNetwork tries to identify the CurrencyNet from address string
func DetectAddressNetwork(addr string) (*chaincfg.Params, error) {

	networkChar := addr[0:1]
	switch networkChar {
	case chaincfg.MainNetParams.NetworkAddressPrefix:
		return &chaincfg.MainNetParams, nil
	case chaincfg.TestNet3Params.NetworkAddressPrefix:
		return &chaincfg.TestNet3Params, nil
	case chaincfg.SimNetParams.NetworkAddressPrefix:
		return &chaincfg.SimNetParams, nil
	}

	return nil, fmt.Errorf("Unknown network type")
}

const (
	btcAddressRegexString            = `^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$` // bitcoin address
	btcAddressUpperRegexStringBech32 = `^BC1[02-9AC-HJ-NP-Z]{7,76}$`       // bitcoin bech32 address https://en.bitcoin.it/wiki/Bech32
	btcAddressLowerRegexStringBech32 = `^bc1[02-9ac-hj-np-z]{7,76}$`
)

var chars = []byte("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")
var bech32Chars = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
var btcAddressRegex = regexp.MustCompile(btcAddressRegexString)
var btcUpperAddressRegexBech32 = regexp.MustCompile(btcAddressUpperRegexStringBech32)
var btcLowerAddressRegexBech32 = regexp.MustCompile(btcAddressLowerRegexStringBech32)

func isP2SHAddress(addr string) bool {
	if !btcAddressRegex.MatchString(addr) {
		return false
	}

	decode := [25]byte{}

	for _, n := range []byte(addr) {
		d := bytes.IndexByte(chars, n)

		for i := 24; i >= 0; i-- {
			d += 58 * int(decode[i])
			decode[i] = byte(d % 256)
			d /= 256
		}
	}
	h := sha256.New()
	_, _ = h.Write(decode[:21])
	d := h.Sum([]byte{})
	h = sha256.New()
	_, _ = h.Write(d)

	validchecksum := [4]byte{}
	computedchecksum := [4]byte{}

	copy(computedchecksum[:], h.Sum(d[:0]))
	copy(validchecksum[:], decode[21:])

	return validchecksum == computedchecksum
}

func isBech32Address(addr string) bool {
	if !btcLowerAddressRegexBech32.MatchString(addr) && !btcUpperAddressRegexBech32.MatchString(addr) {
		return false
	}

	am := len(addr) % 8

	if am == 0 || am == 3 || am == 5 {
		return false
	}

	addr = strings.ToLower(addr)
	hr := []int{3, 3, 0, 2, 3} // the human readable part will always be bc
	addr = addr[3:]
	dp := make([]int, 0, len(addr))

	for _, c := range addr {
		dp = append(dp, strings.IndexRune(bech32Chars, c))
	}

	ver := dp[0]

	if ver < 0 || ver > 16 {
		return false
	}

	if ver == 0 {
		if len(addr) != 42 && len(addr) != 62 {
			return false
		}
	}

	values := append(hr, dp...)
	GEN := []int{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}

	p := 1

	for _, v := range values {
		b := p >> 25
		p = (p&0x1ffffff)<<5 ^ v

		for i := 0; i < 5; i++ {
			if (b>>uint(i))&1 == 1 {
				p ^= GEN[i]
			}
		}
	}

	if p != 1 {
		return false
	}

	b := uint(0)
	acc := 0
	mv := (1 << 5) - 1
	var sw []int

	for _, v := range dp[1 : len(dp)-6] {
		acc = (acc << 5) | v
		b += 5
		for b >= 8 {
			b -= 8
			sw = append(sw, (acc>>b)&mv)
		}
	}

	if len(sw) < 2 || len(sw) > 40 {
		return false
	}

	return true
}

// IsBitcoinAddress takes a string and tries to determine if it is
// a bitcoin address
func IsBitcoinAddress(addr string) bool {
	if ok := isP2SHAddress(addr); ok {
		return ok
	}

	return isBech32Address(addr)
}
