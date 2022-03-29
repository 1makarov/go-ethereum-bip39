package bip39

import (
	"crypto/ecdsa"
	"crypto/sha512"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcutil/hdkeychain"
	"github.com/ethereum/go-ethereum/accounts"
	"golang.org/x/crypto/pbkdf2"
)

func NewSeed(mnemonic, password string) []byte {
	return pbkdf2.Key([]byte(mnemonic), []byte("mnemonic"+password), 2048, 64, sha512.New)
}

func MustParseDerivationPath(path string) (accounts.DerivationPath, error) {
	return accounts.ParseDerivationPath(path)
}

func MnemonicPathToECDSA(mnemonic, password, pathRaw string) (*ecdsa.PrivateKey, error) {
	seed := NewSeed(mnemonic, password)

	path, err := MustParseDerivationPath(pathRaw)
	if err != nil {
		return nil, err
	}

	return SeedPathToECDSA(seed, path)
}

func SeedPathToECDSA(seed []byte, path accounts.DerivationPath) (*ecdsa.PrivateKey, error) {
	key, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return nil, err
	}

	for _, n := range path {
		key, err = key.Derive(n)
		if err != nil {
			return nil, err
		}
	}

	keyEC, err := key.ECPrivKey()
	if err != nil {
		return nil, err
	}

	return keyEC.ToECDSA(), nil
}
