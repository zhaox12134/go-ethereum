package certificateless_key

import (
	"crypto/rand"
	"math/big"
)

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
func (g *IntegerGroup) paramgen(k int) {
	g.P, _ = rand.Prime(rand.Reader, k)
	g.R = &big.Int{}
	g.R.SetInt64(2)
	g.PointGenerator = g.randomGen()
}

var PublicGroup = GeneratePublicGroup()

func GeneratePublicGroup() *IntegerGroup {
	pg := &IntegerGroup{}
	pg.paramgen(1024)
	return pg
}

func (g *IntegerGroup) randomGen() *big.Int {
	result := &big.Int{}

	for {
		h, _ := rand.Int(rand.Reader, g.P)
		if (result.Exp(h, g.R, g.P).Cmp(bigOne) != 0) && (len(h.Bytes()) == 128) { //make sure that the length of private key's byte is 128
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
	P.Mod(P, group.P)
	return x, P
}
