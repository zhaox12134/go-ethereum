package ethapi

import (
	"testing"
)

func TestPrivateAccountAPI_NewAccount(t *testing.T) {
	b := new(Backend)
	nl := new(AddrLocker)
	pa := NewPrivateAccountAPI(*b, nl)
	pa.ListAccounts()
}
