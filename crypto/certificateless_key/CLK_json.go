package certificateless_key

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
)

type CLK_json struct {
	CLprivateKey_x string `json:"cl_private_key_x"`
	CLprivateKey_d string `json:"cl_private_key_d"`
	CLpublicKey_P  string `json:"cl_public_key_p"`
	CLpublicKey_R  string `json:"cl_public_key_r"`
	CLissuer_type  uint8  `json:"cl_issuer_type"`
	Clissuer_Pub   string `json:"cl_issuer_pub"`
}

func (clk *CL_key) Marshal() CLK_json {
	clkjson := CLK_json{
		hex.EncodeToString(clk.PrivateKey.X.Bytes()),
		hex.EncodeToString(clk.PrivateKey.D.Bytes()),
		hex.EncodeToString(clk.PublicKey.P.Bytes()),
		hex.EncodeToString(clk.PublicKey.R.Bytes()),
		clk.IssuerType,
		hex.EncodeToString(clk.IssuerPub.Bytes()),
	}
	return clkjson
}
func (clk *CL_key) Unmarshal(jsonbytes []byte) error {
	clkjson := new(CLK_json)
	err := json.Unmarshal(jsonbytes, &clkjson)
	if err != nil {
		return err
	}
	//clk, err = crypto.HexToCLK(clkjson.CLprivateKey_x, clkjson.CLprivateKey_d, clkjson.CLpublicKey_P, clkjson.CLpublicKey_R)

	clk.PrivateKey = new(PrivateKey)
	clk.PrivateKey.X = new(big.Int)
	clk.PrivateKey.D = new(big.Int)
	clk.PublicKey = new(PublicKey)
	clk.PublicKey.P = new(big.Int)
	clk.PublicKey.R = new(big.Int)
	clk.IssuerPub = new(big.Int)

	x, _ := hex.DecodeString(clkjson.CLprivateKey_x)
	clk.PrivateKey.X.SetBytes(x)

	d, _ := hex.DecodeString(clkjson.CLprivateKey_d)
	clk.PrivateKey.D.SetBytes(d)

	P, _ := hex.DecodeString(clkjson.CLpublicKey_P)
	clk.PublicKey.P.SetBytes(P)

	R, _ := hex.DecodeString(clkjson.CLpublicKey_R)
	clk.PublicKey.R.SetBytes(R)

	clk.IssuerType = clkjson.CLissuer_type

	issuerpub, _ := hex.DecodeString(clkjson.Clissuer_Pub)
	clk.IssuerPub.SetBytes(issuerpub)

	clk.Group = PublicGroup
	return nil
}
