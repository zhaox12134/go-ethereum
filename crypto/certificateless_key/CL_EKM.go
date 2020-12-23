package certificateless_key

import (
	excrypto "crypto"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"io"
	"math/big"
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
}

var bigOne = big.NewInt(1)
var bigZero = big.NewInt(0)

func GenerateKey() *CL_key {
	//choose random big.int x and compute P = x * generator
	cl_key := &CL_key{}

	cl_key.Group = PublicGroup

	cl_key.PrivateKey.X = cl_key.Group.randomGen()
	cl_key.PublicKey.P.Mul(cl_key.PrivateKey.X, cl_key.Group.PointGenerator)
	cl_key.PublicKey.P.Mod(cl_key.PublicKey.P, cl_key.Group.P)
	return cl_key
}

//KGC generate R and D to complete CL-key
func GenPartialKey_dR(group *IntegerGroup, ID []byte, P *big.Int, x *big.Int) (*big.Int, *big.Int) {
	r := group.randomGen()
	R := &big.Int{}
	R.Mul(r, group.PointGenerator)
	d := &big.Int{}

	h0_result := &big.Int{}
	h0_result.SetBytes(h0(ID, P, x))
	h0_result.Mod(h0_result, group.P)

	x.Mul(x, h0_result)
	x.Mod(x, group.P)

	d.Add(r, x)
	d.Mod(d, group.P)

	return R, d
}

type CLK_json struct {
	CLprivateKey_x string `json:"cl_private_key_x"`
	CLprivateKey_d string `json:"cl_private_key_d"`
	CLpublicKey_P  string `json:"cl_public_key_p"`
	CLpublicKey_R  string `json:"cl_public_key_r"`
}

//transform a cl_key object to json types
func (clk *CL_key) ToBytes() []byte {
	clkjson := CLK_json{
		hex.EncodeToString(clk.PrivateKey.X.Bytes()),
		hex.EncodeToString(clk.PrivateKey.D.Bytes()),
		hex.EncodeToString(clk.PublicKey.P.Bytes()),
		hex.EncodeToString(clk.PublicKey.R.Bytes())}
	clk_byt, _ := json.Marshal(clkjson)
	return clk_byt
}

//transform a json file's types to cl_key object
func GenerateCLKFromByte(jsonbytes []byte) *CL_key {
	ret := &CL_key{}
	err := ret.BytesToCLK(jsonbytes)
	if err != nil {
		return nil
	}
	return ret
}
func (clk *CL_key) BytesToCLK(jsonbytes []byte) error {
	clkjson := new(CLK_json)
	err := json.Unmarshal(jsonbytes, &clkjson)
	if err != nil {
		return err
	}
	//clk, err = crypto.HexToCLK(clkjson.CLprivateKey_x, clkjson.CLprivateKey_d, clkjson.CLpublicKey_P, clkjson.CLpublicKey_R)
	x, _ := hex.DecodeString(clkjson.CLprivateKey_x)
	clk.PrivateKey.X.SetBytes(x)
	d, _ := hex.DecodeString(clkjson.CLprivateKey_d)
	clk.PrivateKey.D.SetBytes(d)
	P, _ := hex.DecodeString(clkjson.CLpublicKey_P)
	clk.PublicKey.P.SetBytes(P)
	R, _ := hex.DecodeString(clkjson.CLpublicKey_R)
	clk.PublicKey.R.SetBytes(R)

	clk.Group = PublicGroup
	return nil
}

//func (clk *CL_key) ToBytes() []byte {
//	var byt []byte
//	byt = append(clk.PrivateKey.ToByte(), clk.PublicKey.ToByte()...)
//	byt = append(byt, clk.Group.ToByte()...)
//	return byt
//}
func (clk *CL_key) Getx() big.Int {
	return *clk.PrivateKey.X
}
func (clk *CL_key) Getd() big.Int {
	return *clk.PrivateKey.D
}
func (clk *CL_key) Public() PublicKey {
	return *clk.PublicKey
}
func (clk *CL_key) Sign(rand io.Reader, digest []byte, opts CLSignerOpts) (signature []byte, err error) {
	if clk.PrivateKey.X.Cmp(bigZero)*clk.PublicKey.P.Cmp(bigZero) == 0 { //x or P is zero
		return nil, fmt.Errorf("no clk_private key")
	}
	if clk.PrivateKey.D.Cmp(bigZero)*clk.PublicKey.R.Cmp(bigZero) == 0 { //D or R is zero
		hash_input := append(digest, clk.PrivateKey.X.Bytes()...)
		hash_result := sha256.Sum256(hash_input)
		return hash_result[:], nil
	} else {
		hash_input := append(digest, clk.PrivateKey.X.Bytes()...)
		hash_input = append(hash_input, clk.PrivateKey.D.Bytes()...)
		hash_result := sha256.Sum256(hash_input)
		return hash_result[:], nil
	}

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

}
