package certificateless_key

import (
	"encoding/hex"
	"math/big"
	"testing"
)

func TestH0(t *testing.T) {
	var x = new(CL_key)
	x.PrivateKey = new(PrivateKey)
	x.PublicKey = new(PublicKey)
	x.PrivateKey.X = new(big.Int)
	x.PrivateKey.X = big.NewInt(100)
	bef := x.PrivateKey.X

	GeneratePublicGroup()
	x.Group = PublicGroup
	st := hex.EncodeToString(FromCLK(x, "x"))
	l, _ := HexToCLK(st, "", "", "")

	println(l.PrivateKey.X.Cmp(bef))
}
func Testgetone(t *testing.T) {

}
