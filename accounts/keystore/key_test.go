package keystore

import (
	"github.com/ethereum/go-ethereum/crypto/certificateless_key"
	"testing"
)

func TestStoreKey(t *testing.T) {
	//ran := new(io.Reader)
	//key, _:=newKey(*ran)
	//key := certificateless_key.GenerateKey()
}

// TestImportExport tests the import functionality of a keystore.
func TestImportCLK(t *testing.T) {
	//dir, ks := tmpKeyStore(t, true)
	//defer os.RemoveAll(dir)
	////key, err := crypto.GenerateKey()
	//y, err := crypto.GenerateCLKey()
	//if err != nil {
	//	t.Fatalf("failed to generate key: %v", key)
	//}
	//if _, err = ks.ImportECDSA(key, "old"); err != nil {
	//	t.Errorf("importing failed: %v", err)
	//}
	//if _, err = ks.ImportECDSA(key, "old"); err == nil {
	//	t.Errorf("importing same key twice succeeded")
	//}
	//if _, err = ks.ImportECDSA(key, "new"); err == nil {
	//	t.Errorf("importing same key twice succeeded")
	//}
}

func TestKeyStore_Accounts(t *testing.T) {
	ks := NewKeyStore("testKeystore", StandardScryptN, StandardScryptP) //new(KeyStore)
	clk1 := certificateless_key.GenerateKey()
	//println(crypto.ClPubKeyToAddress(clk1).String())

	//clk2 := certificateless_key.GenerateKey()
	////println(crypto.ClPubKeyToAddress(clk2).String())
	newKeyFromCL(clk1)

	ac1, _ := ks.NewAccount("zx1234")
	ac2, _ := ks.NewAccount("xx1412")
	println(ac1.Address.String())
	println(ac2.Address.String())
}
