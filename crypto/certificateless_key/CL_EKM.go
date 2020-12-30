package certificateless_key

import (
	excrypto "crypto"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
)

const ( //to tell apart CLK issuer
	Athority = uint8(0) //BS:Athority issue the key to BS
	KGC      = uint8(1) //H-SENSOR:BS(KGC) issue to H-sensor
	H_SENSOR = uint8(2) //L-SENSOR
	L_SENSOR = uint8(3)
)

type PrivateKey struct {
	X *big.Int
	D *big.Int
}

func (sk *PrivateKey) ToByte() []byte {
	var byt []byte
	if sk.X != nil {
		byt = append(byt, sk.X.Bytes()...)
	}
	if sk.D != nil {
		byt = append(byt, sk.D.Bytes()...)
	}
	return byt
}

type PublicKey struct {
	P *big.Int
	R *big.Int
}

type CLSignerOpts struct {
	Hash excrypto.Hash
}

func (cls *CLSignerOpts) HashFunc() excrypto.Hash {
	return cls.Hash
}

type CLDecrypterOpts CLSignerOpts

func (pk *PublicKey) ToByte() []byte {
	var byt []byte
	if pk.P != nil {
		byt = append(byt, pk.P.Bytes()...)
	}
	if pk.R != nil {
		byt = append(byt, pk.R.Bytes()...)
	}
	return byt
}

type CL_key struct {
	PublicKey  *PublicKey
	Group      *IntegerGroup
	PrivateKey *PrivateKey

	IssuerType uint8
	IssuerPub  *big.Int //
}

var bigOne = big.NewInt(1)
var bigZero = big.NewInt(0)
var BS = GenBS()

func GenBS() *CL_key {
	bs := GenerateKey()
	p := new(big.Int)
	p.Mul(bs.PrivateKey.X, bs.Group.PointGenerator)
	p.Mod(p, bs.Group.P)
	bs.PublicKey.P = p

	//for BS, x is random,P(Pub) = x * generator
	//and d and R is nil
	bs.IssuerType = Athority
	return bs
}

func GenerateKey() *CL_key {
	//choose random big.int x and compute P = x * generator
	cl_key := new(CL_key)
	cl_key.PrivateKey = new(PrivateKey)
	cl_key.PublicKey = new(PublicKey)

	cl_key.Group = PublicGroup
	cl_key.PrivateKey.X = cl_key.Group.randomGen()
	cl_key.PublicKey.P = new(big.Int)
	cl_key.PublicKey.P.Mul(cl_key.PrivateKey.X, cl_key.Group.PointGenerator)
	cl_key.PublicKey.P.Mod(cl_key.PublicKey.P, cl_key.Group.P)

	cl_key.PrivateKey.D = big.NewInt(0)
	cl_key.PublicKey.R = big.NewInt(0)
	cl_key.IssuerPub = big.NewInt(0)
	return cl_key
}

//transform a cl_key object to json types
func (clk *CL_key) ToBytes() []byte {
	clkjson := clk.Marshal()
	clk_byt, _ := json.Marshal(clkjson)
	return clk_byt
}

//transform a json file's types to cl_key object
func GenerateCLKFromByte(jsonbytes []byte) *CL_key {
	ret := &CL_key{}
	err := ret.Unmarshal(jsonbytes)
	if err != nil {
		return nil
	}
	return ret
}

//func (clk *CL_key) BytesToCLK(jsonbytes []byte) error {
//	clkjson := new(CLK_json)
//	err := json.Unmarshal(jsonbytes, &clkjson)
//	if err != nil {
//		return err
//	}
//	//clk, err = crypto.HexToCLK(clkjson.CLprivateKey_x, clkjson.CLprivateKey_d, clkjson.CLpublicKey_P, clkjson.CLpublicKey_R)
//	x, _ := hex.DecodeString(clkjson.CLprivateKey_x)
//	clk.PrivateKey.X.SetBytes(x)
//	d, _ := hex.DecodeString(clkjson.CLprivateKey_d)
//	clk.PrivateKey.D.SetBytes(d)
//	P, _ := hex.DecodeString(clkjson.CLpublicKey_P)
//	clk.PublicKey.P.SetBytes(P)
//	R, _ := hex.DecodeString(clkjson.CLpublicKey_R)
//	clk.PublicKey.R.SetBytes(R)
//
//	clk.Group = PublicGroup
//	return nil
//}

//compare clk and x
func (clk *CL_key) Equal(x *CL_key) bool {
	return clk.PrivateKey.D.Cmp(x.PrivateKey.D) == 0 &&
		clk.PrivateKey.X.Cmp(x.PrivateKey.X) == 0 &&
		clk.PublicKey.P.Cmp(x.PublicKey.P) == 0 &&
		clk.PublicKey.R.Cmp(x.PublicKey.R) == 0 &&
		clk.IssuerPub.Cmp(x.IssuerPub) == 0 &&
		clk.IssuerType == x.IssuerType
}

func (clk *CL_key) Getx() big.Int {
	return *clk.PrivateKey.X
}
func (clk *CL_key) Getd() big.Int {
	return *clk.PrivateKey.D
}
func (clk *CL_key) Public() PublicKey {
	return *clk.PublicKey
}

//KGC generate R and D to complete CL-key
func (clk *CL_key) GenPartialKey(ID []byte, P *big.Int) (*big.Int, *big.Int, uint8, *big.Int) {
	r := clk.Group.randomGen()

	R := &big.Int{}
	R.Mul(r, clk.Group.PointGenerator)
	R.Mod(R, clk.Group.P) //R = r * generator mod p

	d := &big.Int{}

	h0_result := &big.Int{}
	h0_result.SetBytes(h0(ID, R, P))
	h0_result.Mod(h0_result, clk.Group.P) // h0(id,R,P) mod p

	x := new(big.Int)
	Pub := new(big.Int)
	// IssuerPub
	if clk.IssuerType == Athority {
		//take x as secret key when BS Generate d and R to H-sensor
		x.Set(clk.PrivateKey.X)

		Pub.Set(clk.PublicKey.P) //accordingly, Pub is clk.PublicKey.P
	} else {
		x.Add(clk.PrivateKey.X, clk.PrivateKey.D) // take x + d as secret key x when H-sensor Generate d and R to others
		x.Mod(x, clk.Group.P)

		//Pub.Add(clk.PublicKey.P, clk.PublicKey.R)
		//Pub.Mod(Pub, clk.Group.P)
		//
		//pub_h0 := new(big.Int) //for H-sensor, pub_h0 is (pub_bs * h0) mod p
		//pub_h0.Mul(clk.IssuerPub, h0_result)
		//pub_h0.Mod(pub_h0, clk.Group.P)
		//
		//Pub.Add(Pub, pub_h0) // Pub = P_h + R_h + Pub_bs * h0(ID_h, R_h, P_h)
		//Pub.Mod(Pub, clk.Group.P)
		//Pub := new(big.Int)
		//h0_result := new(big.Int)
		Pub.Add(clk.PublicKey.P, clk.PublicKey.R)
		h0_result.SetBytes(h0(ID, clk.PublicKey.R, clk.PublicKey.P))
		Pub.Add(Pub, h0_result.Mul(h0_result, clk.IssuerPub).Mod(h0_result, clk.Group.P)).Mod(Pub, clk.Group.P)
		//println("generate pub with x and d")
		//println(Pub.Int64())
	}
	x_h0 := new(big.Int)
	x_h0.Mul(x, h0_result)
	x_h0.Mod(x_h0, clk.Group.P) //x_h0 = x * h0() mod P

	d.Add(r, x_h0) //d = r + x * h0
	d.Mod(d, clk.Group.P)
	//println("pub: ",Pub.Int64())
	return R, d, clk.IssuerType + 1, Pub
}

func (clk *CL_key) Sign(digest []byte) (signature1 []byte, signature2 []byte, err error) {
	dig1 := new(big.Int) //transform digest to big.int, and store it in dig
	dig1.SetBytes(digest)
	if clk.PrivateKey.X.Cmp(bigZero)*clk.PublicKey.P.Cmp(bigZero) == 0 { //x or P is zero
		return nil, nil, fmt.Errorf("no clk_private key")
	} else {
		dig1.Mul(dig1, clk.PrivateKey.X)
		dig1.Mod(dig1, clk.Group.P)
	}
	if clk.PrivateKey.D == nil || clk.PublicKey.R == nil { //D or R is zero
		return dig1.Bytes(), nil, nil
	} else {
		dig2 := new(big.Int) //transform digest to big.int, and store it in dig
		dig2.SetBytes(digest)
		dig2.Mul(dig2, clk.PrivateKey.D)
		dig2.Mod(dig2, clk.Group.P)
		return dig1.Bytes(), dig2.Bytes(), nil
	}
}

//verify x's signature by P, and d's by R

func VerifySignature(digest, sign1, sign2, ID []byte, P, R, Pub *big.Int, issuertype uint8) (bool, bool) {
	if sign1 == nil {
		return false, false
	}
	dig1 := new(big.Int)
	s1 := new(big.Int)

	dig1.SetBytes(digest)
	s1.SetBytes(sign1)
	// s1 = X * digest
	s1.Mul(s1, PublicGroup.PointGenerator) //s1 = s1 * generator
	s1.Mod(s1, PublicGroup.P)              //   =  X * digest * generator

	dig1.Mul(dig1, P) //dig1 = digest * P
	dig1.Mod(dig1, PublicGroup.P)

	if issuertype == Athority { // if the signature from BS, then just verify the sign1 is match to P
		return s1.Cmp(dig1) == 0, true
	} else {
		dig2 := new(big.Int)
		s2 := new(big.Int)
		dig2.SetBytes(digest)
		s2.SetBytes(sign2)

		// s2 = D * digest
		s2.Mul(s2, PublicGroup.PointGenerator) //s2 = D * generator
		s2.Mod(s2, PublicGroup.P)

		prph := new(big.Int) //named by P + R + pub_bs * h0

		h0_result := new(big.Int)
		h0_result.SetBytes(h0(ID, R, P))
		h0_result.Mod(h0_result, PublicGroup.P)

		pub := new(big.Int)
		pub.Mul(Pub, h0_result)
		pub.Mod(pub, PublicGroup.P) //pub = pub * h0

		prph.Add(pub, R)
		prph.Mod(prph, PublicGroup.P)

		dig2.Mul(dig2, prph) //dig2 = digest *(R + pub_bs * h0)
		dig2.Mod(dig2, PublicGroup.P)
		//println(s2.Int64())
		//println(dig2.Int64())
		return ((s1.Cmp(dig1)) == 0), ((s2.Cmp(dig2)) == 0)
	}
}
func Trans() {

}
func HexToCLK(x, d, P, R string) (*CL_key, error) {
	byt_x, _ := hex.DecodeString(x)
	byt_d, _ := hex.DecodeString(d)
	byt_P, _ := hex.DecodeString(P)
	byt_R, _ := hex.DecodeString(R)
	//byt_mod, _ := hex.DecodeString(mod)
	//byt_r, _ := hex.DecodeString(r)
	//byt_generator, _ := hex.DecodeString(generator)

	priv_x := &big.Int{}
	priv_x.SetBytes(byt_x)

	priv_d := &big.Int{}
	priv_d.SetBytes(byt_d)

	pub_P := &big.Int{}
	pub_P.SetBytes(byt_P)

	pub_R := &big.Int{}
	pub_R.SetBytes(byt_R)

	//group_mod := &big.Int{}
	//group_mod.SetBytes(byt_mod)
	//
	//group_r := &big.Int{}
	//group_r.SetBytes(byt_r)
	//
	//group_gen := &big.Int{}
	//group_gen.SetBytes(byt_generator)

	ret := &CL_key{
		PrivateKey: &PrivateKey{
			priv_x,
			priv_d,
		},
		PublicKey: &PublicKey{
			pub_P,
			pub_R,
		},
		Group: PublicGroup,
	}
	return ret, nil
}

func FromCLK(clk *CL_key, key string) []byte {
	if clk == nil {
		return nil
	}
	switch key {
	case "x":
		x := clk.PrivateKey.X
		return x.Bytes()
	case "d":
		d := clk.PrivateKey.D
		return d.Bytes()
	case "P":
		P := clk.PublicKey.P
		return P.Bytes()
	case "R":
		R := clk.PublicKey.R
		return R.Bytes()
		//case "mod":
		//	mod := clk.Group.P
		//	return mod.Bytes()
		//case "r":
		//	r := clk.Group.R
		//	return r.Bytes()
		//case "gen":
		//	gen := clk.Group.PointGenerator
		//	return gen.Bytes()
	}

	return nil
}

func (clk *CL_key) Decrypt(rand io.Reader, msg []byte, opts CLDecrypterOpts) (plaintext []byte, err error) {
	x := []byte{}
	return x, nil
}
func (clk *CL_key) setPartialKey(R *big.Int, d *big.Int, Typ uint8, Pub *big.Int) {
	clk.PublicKey.R = R
	clk.PrivateKey.D = d
	clk.IssuerType = Typ
	clk.IssuerPub = Pub
}
func (clk *CL_key) SelfCheck(ID []byte) (bool, bool) { //check whether the relationship between x an P, d and R
	X := new(big.Int)
	X.Set(clk.PrivateKey.X)
	D := new(big.Int)
	D.Set(clk.PrivateKey.D)
	P := new(big.Int)
	P.Set(clk.PublicKey.P)
	R := new(big.Int)
	R.Set(clk.PublicKey.R)

	h0_result := new(big.Int)
	h0_result.SetBytes(h0(ID, R, P))
	h0_result.Mod(h0_result, PublicGroup.PointGenerator)
	h0_result.Mul(clk.IssuerPub, h0_result)
	h0_result.Mod(h0_result, PublicGroup.PointGenerator)
	//h0_result = pub * h0 mod p

	var (
		flag1 = false
		flag2 = false
	)
	if X.Mul(X, PublicGroup.PointGenerator).Mod(X, PublicGroup.P).Cmp(P) == 0 {
		flag1 = true
	}
	if D.Mul(D, PublicGroup.PointGenerator).Mod(X, PublicGroup.P).Cmp(R.Add(R, h0_result).Mod(X, PublicGroup.P)) == 0 {
		flag2 = true
	}

	//if(clk.PrivateKey.X)
	return flag1, flag2
}
func (clk *CL_key) rew(id []byte) {
	pub := new(big.Int)
	h0_result := new(big.Int)
	pub.Add(clk.PublicKey.P, clk.PublicKey.R)
	h0_result.SetBytes(h0(id, clk.PublicKey.R, clk.PublicKey.P))
	pub.Add(pub, h0_result.Mul(h0_result, clk.IssuerPub).Mod(h0_result, clk.Group.P)).Mod(pub, clk.Group.P)

	x_d := new(big.Int)
	x_d.Add(clk.PrivateKey.X, clk.PrivateKey.D)
	x_d.Mod(x_d, clk.Group.P)
	x_d.Mul(x_d, clk.Group.PointGenerator)
	x_d.Mod(x_d, clk.Group.P)
	println("************")
	//println(clk.PrivateKey.X.Int64())
	//println(clk.PrivateKey.D.Int64())
	//println(clk.PublicKey.P.Int64())
	//println(clk.PublicKey.R.Int64())
	//println(clk.IssuerPub.Int64())
	println(x_d.Int64())
	println(pub.Int64())
	println(x_d.Cmp(pub))
}
