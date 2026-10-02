package mysql

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestDebugDriverScrambleHunt2(t *testing.T) {
	sessPw := "vHbotGs04fNxoWpdZmwk07byNOuxP-VFWJb4YAdv1tY"
	relayScramble, _ := hex.DecodeString("63816bea9906d8c0b19cff1ada058ea723be9527")
	want, _ := hex.DecodeString("3c4df746b18d99d974e38a56e77a32601b38fda4")
	pws := map[string]string{"sess": sessPw, "empty": "", "realpw": "REALPW"}
	scs := map[string][]byte{
		"relay20":     relayScramble,
		"relay+NUL":   append(append([]byte{}, relayScramble...), 0),
		"relay12":     relayScramble[:12],
		"relay16":     relayScramble[:16],
		"relay8":      relayScramble[:8],
		"padded32":    append(append([]byte{}, relayScramble...), make([]byte, 12)...),
	}
	for pwName, pw := range pws {
		for scName, sc := range scs {
			if bytes.Equal(nativeToken(pw, sc), want) {
				t.Logf("MATCH native pw=%s sc=%s", pwName, scName)
			}
			if bytes.Equal(fastToken(pw, sc), want) {
				t.Logf("MATCH fast pw=%s sc=%s", pwName, scName)
			}
		}
	}
	t.Logf("hunt done (nothing printed above = no match)")
}
