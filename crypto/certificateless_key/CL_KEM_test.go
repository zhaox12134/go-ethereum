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

	//GeneratePublicGroup()
	x.Group = PublicGroup
	st := hex.EncodeToString(FromCLK(x, "x"))
	l, _ := HexToCLK(st, "", "", "")

	println(l.PrivateKey.X.Cmp(bef))
}
func TestGenerateKey(t *testing.T) {
	//GeneratePublicGroup()
	var i = 1
	for ; i < 10000; i++ {
		x := GenerateKey()
		if len(x.PrivateKey.X.Bytes()) != 128 {
			println(len(x.PrivateKey.X.Bytes()))
		}
	}
}
func TestSign(t *testing.T) {
	//GeneratePublicGroup()
	x := GenerateKey()

	//var msg = "hello world!"
	//msg_byt,_ := hex.DecodeString(msg)
	//digest := sha256.Sum256(msg_byt)
	//rand := new(io.Reader)
	//opt := CLSignerOpts{}

	//var bs_x = PublicGroup.randomGen()
	//bs_pub := new(big.Int)
	//bs_pub.Mul(bs_x,PublicGroup.PointGenerator)
	//bs_pub.Mod(bs_pub,PublicGroup.P)

	var id = PublicGroup.randomGen().Bytes()
	println("bs gen partial key to x")
	x.setPartialKey(BS.GenPartialKey(id, x.PublicKey.P))

	y := GenerateKey()

	var id1 = PublicGroup.randomGen().Bytes()
	println("x gen partial key to y")
	y.setPartialKey(x.GenPartialKey(id1, y.PublicKey.P))
	//println(y.SelfCheck(id1))
	//println(x.SelfCheck(id))

	//sig_x,sig_d,_ := x.Sign(*rand, digest[:], opt)
	//println(VerifySignature(digest[:], sig_x, sig_d, id, x.PublicKey.P, x.PublicKey.R, x.IssuerPub, x.IssuerType))

	//println(y.SelfCheck(id1))
	//sig_x,sig_d,_ = y.Sign(*rand, digest[:], opt)
	//println(VerifySignature(digest[:], sig_x, sig_d, id1, y.PublicKey.P, y.PublicKey.R, y.IssuerPub, y.IssuerType))
	//println(x.IssuerType)
	//println(y.IssuerType)

	pub := new(big.Int)
	pub.SetBytes(h0(id, x.PublicKey.R, x.PublicKey.P))
	pub.Mod(pub, PublicGroup.P)
	H0 := pub

	pub.Mul(x.IssuerPub, pub)
	pub.Mod(pub, PublicGroup.P)

	pub.Add(pub, x.PublicKey.P)
	pub.Add(pub, x.PublicKey.R)
	pub.Mod(pub, PublicGroup.P)

	println(x.PublicKey.P.Int64())
	println(x.PublicKey.R.Int64())
	println(H0.Int64())
	println(BS.PublicKey.P.Int64())
	println(y.IssuerPub.Int64())

	println(y.SelfCheck(id1))
	println(y.IssuerPub.Cmp(pub))
	//x.rew(id)
	//y.rew(id1)
}
func TestTrans(t *testing.T) {
	X := PublicGroup.randomGen()
	Y := PublicGroup.randomGen()
	Z := new(big.Int)
	Z.Mul(X, Y)
	X_BYT := X.Bytes()
	Y.SetBytes(X_BYT)
	println(X.Cmp(Y))
}
func TestCL_key_Marshal(t *testing.T) {
	x := GenerateKey()
	var id = PublicGroup.randomGen().Bytes()
	x.setPartialKey(BS.GenPartialKey(id, x.PublicKey.P))
	marshal_result := x.ToBytes()

	y := GenerateCLKFromByte(marshal_result)

	println(x.Equal(y))

}
func TestTrans2(t *testing.T) {
	x := []byte{0x14, 0x13, 16}
	println(x)
	y := hex.EncodeToString(x)
	println(y)
	//z ,_:= hex.DecodeString(y)

}
