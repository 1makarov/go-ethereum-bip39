package bip39

import (
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"testing"
)

func TestSeedBip39PathToECDSA(t *testing.T) {
	testTable := []struct {
		mnemonic, password, path string
		expectedPrivateKeyHex    string
	}{
		{
			mnemonic:              "sentence garment husband situate hundred bargain genre erosion unveil hello thumb bundle rude seed cheese",
			password:              "",
			path:                  "m/44'/60'/0'/0/0",
			expectedPrivateKeyHex: "0x593981e612fecd9382646ea71226d27a078ff292162f3ed6af49098e3d45daf4",
		},
		{
			mnemonic:              "sentence garment husband situate hundred bargain genre erosion unveil hello thumb bundle rude seed cheese",
			password:              "",
			path:                  "m/44'/60'/0'/0/1",
			expectedPrivateKeyHex: "0x9b70a06e645127807fa6000cd37012ef2106ceda806b202f0d182af9f58eb2df",
		},
		{
			mnemonic:              "sentence garment husband situate hundred bargain genre erosion unveil hello thumb bundle rude seed cheese",
			password:              "qwerty",
			path:                  "m/44'/60'/0'/0/0",
			expectedPrivateKeyHex: "0xe3744f9f0841e6dd5ecf353561229570d3b8917cf5f9982741ef0789339524a9",
		},
	}

	for i, tc := range testTable {
		seed := NewSeed(tc.mnemonic, tc.password)

		path, err := MustParseDerivationPath(tc.path)
		if err != nil {
			t.Errorf("[%d] mustParseDerivationPath error: %v", i, err)
			continue
		}

		privateKey, err := SeedPathToECDSA(seed, path)
		if err != nil {
			t.Errorf("[%d] seedBip39PathToECDSA error: %v", i, err)
			continue
		}

		privateKeyBytes := crypto.FromECDSA(privateKey)
		privateKeyHex := hexutil.Encode(privateKeyBytes)

		if privateKeyHex == tc.expectedPrivateKeyHex {} else {
			t.Errorf("[%d] incorrect result, waiting: %v, received: %v", i, tc.expectedPrivateKeyHex, privateKeyHex)
		}
	}
}
