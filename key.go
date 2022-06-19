
package jwt

import (
	"crypto/rand"
	"crypto/sha512"
)

func NewKey(data []byte)(key []byte){
	h := sha512.New()
	h.Write(data)
	return h.Sum(nil)
}

func NewKeyWithString(data string)([]byte){
	h := sha512.New()
	h.Write(([]byte)(data))
	return h.Sum(nil)
}

func GenerateBytes()(data []byte, err error){
	data = make([]byte, sha512.BlockSize)
	_, err = rand.Read(data)
	if err != nil { return }
	return
}
