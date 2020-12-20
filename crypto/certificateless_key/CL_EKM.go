package certificateless_key

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
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
	Hash crypto.Hash
}

func (cls *CLSignerOpts) HashFunc() crypto.Hash {
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

type IntegerGroup struct {
	P              *big.Int
	R              *big.Int
	PointGenerator *big.Int
	//q *big.Int
}

func (g *IntegerGroup) ToByte() []byte {
	var byt []byte
	byt = append(byt, g.P.Bytes()...)
	byt = append(byt, g.PointGenerator.Bytes()...)
	//byt = append(byt, g.R.Bytes()...)

	return byt
}

type CL_key struct {
	PublicKey  *PublicKey
	Group      *IntegerGroup
	PrivateKey *PrivateKey
}

var bigOne = big.NewInt(1)
var bigZero = big.NewInt(0)

func GenerateKey(k int) *CL_key {
	//choose random big.int x and compute P = x * generator
	cl_key := &CL_key{}

	cl_key.Group.paramgen(k)

	cl_key.PrivateKey.X = cl_key.Group.randomGen()
	cl_key.PublicKey.P.Mul(cl_key.PrivateKey.X, cl_key.Group.PointGenerator)
	cl_key.PublicKey.P.Mod(cl_key.PublicKey.P, cl_key.Group.P)
	return cl_key
}
func (g *IntegerGroup) paramgen(k int) {
	g.P, _ = rand.Prime(rand.Reader, k)

	g.PointGenerator = g.randomGen()
}

func (g *IntegerGroup) randomGen() *big.Int {
	result := &big.Int{}

	for {
		h, _ := rand.Int(rand.Reader, g.P)
		if result.Exp(h, g.R, g.P).Cmp(bigOne) != 0 {
			return h
		}
	}
}
func (g *IntegerGroup) randomPrimeGen(k int) *big.Int {
	result := &big.Int{}
	for {
		h, _ := rand.Prime(rand.Reader, k)
		if result.Exp(h, g.R, g.P).Cmp(bigOne) != 0 {
			return h
		}
	}
}

//node generate x and P as partial key
func GenPartialKey_xP(group *IntegerGroup) (*big.Int, *big.Int) {
	x := group.randomGen()
	P := &big.Int{}
	P.Mul(x, group.PointGenerator)
	return x, P
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

func (clk *CL_key) ToBytes() []byte {
	var byt []byte
	byt = append(clk.PrivateKey.ToByte(), clk.PublicKey.ToByte()...)
	byt = append(byt, clk.Group.ToByte()...)
	return byt
}
func (clk *CL_key) Getx() big.Int {
	return *clk.PrivateKey.X
}
func (clk *CL_key) Getd() big.Int {
	return *clk.PrivateKey.D
}
func (clk *CL_key) Public() PublicKey {
	return clk.PublicKey
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
func (clk *CL_key) Decrypt(rand io.Reader, msg []byte, opts CLDecrypterOpts) (plaintext []byte, err error) {

}
func h0(binary1 []byte, g1 *big.Int, g2 *big.Int) []byte {
	result := &big.Int{}

	b1 := &big.Int{}
	b1.SetBytes(binary1)

	result.Mul(b1, g1)
	result.Mul(result, g2)

	hash_result := sha256.Sum256(result.Bytes())
	return hash_result[:]
}
func h1(g1 *big.Int, g2 *big.Int, g3 *big.Int, binary1 []byte, g4 *big.Int) []byte {
	result := &big.Int{}
	b1 := &big.Int{}
	b1.SetBytes(binary1)

	result.Mul(g1, g2)
	result.Mul(result, g3)
	result.Mul(result, g4)
	result.Mul(result, b1)
	hash_result := sha256.Sum256(result.Bytes())
	return hash_result[:]
}
func h2(g1 *big.Int, binary1 []byte, g2 *big.Int, binary2 []byte, g3 *big.Int, binary3 []byte, g4 *big.Int) *big.Int {
	b1 := &big.Int{}
	b1.SetBytes(binary1)
	b2 := &big.Int{}
	b2.SetBytes(binary2)
	b3 := &big.Int{}
	b3.SetBytes(binary3)

	result := &big.Int{}
	result.Mul(g1, b1)
	result.Mul(result, g2)
	result.Mul(result, b2)
	result.Mul(result, g3)
	result.Mul(result, b3)
	result.Mul(result, g4)
	return result
}
func h3(g1 *big.Int, binary1 []byte, g2 *big.Int, binary2 []byte, g3 *big.Int, binary3 []byte, g4 *big.Int) *big.Int {
	result := make([]byte, 0)

	result = append(result, g1.Bytes()...)
	result = append(result, binary1...)
	result = append(result, g2.Bytes()...)
	result = append(result, binary2...)
	result = append(result, g3.Bytes()...)
	result = append(result, binary3...)
	result = append(result, g4.Bytes()...)

	result_int := &big.Int{}
	result_int.SetBytes(result)
	return result_int
}
