package certificateless_key

import (
	"crypto/sha256"
	"math/big"
)

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
