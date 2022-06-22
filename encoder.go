
package jwt

import (
	"crypto/hmac"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

var (
	NotVaildErr = errors.New("Not a vaild jwt")
	NotVerifiedErr = errors.New("Not a verified jwt")
	ExpiredErr = errors.New("Token expired")
	NotBeforeErr = errors.New("Token is not in activity")
	SubjectNotMatch = errors.New("Token subject not match")
)

type Map = map[string]interface{}

func Encode(header *Header, payload interface{}, key []byte)(token []byte, err error){
	if header == nil {
		header = NewHeader()
	}
	var head, body []byte
	header.IssuedAt = time.Now()
	head, err = json.Marshal(header)
	if err != nil { return }
	body, err = json.Marshal(payload)
	if err != nil { return }
	mac := calcMAC(header.Signer, head, body, key)
	lh, lb, lm := base64.RawURLEncoding.EncodedLen(len(head)), base64.RawURLEncoding.EncodedLen(len(body)), base64.RawURLEncoding.EncodedLen(len(mac))
	token = make([]byte, lh + lb + lm + 2)
	base64.RawURLEncoding.Encode(token[:lh], head)
	base64.RawURLEncoding.Encode(token[lh + 1:lh + lb + 1], body)
	base64.RawURLEncoding.Encode(token[lh + lb + 2:], mac)
	token[lh] = '.'
	token[lh + lb + 1] = '.'
	return
}

func EncodeToString(header *Header, payload interface{}, key []byte)(token string, err error){
	var tk []byte
	tk, err = Encode(header, payload, key)
	if err != nil { return }
	return (string)(tk), nil
}

func Decode(token []byte, ptr interface{}, key []byte)(header *Header, err error){
	return DecodeString((string)(token), ptr, key)
}

func DecodeString(token string, ptr interface{}, key []byte)(header *Header, err error){
	var (
		head, body, mac []byte
		i int
	)
	i = strings.IndexByte(token, '.')
	if i < 0 {
		return nil, NotVaildErr
	}
	head, err = base64.RawURLEncoding.DecodeString(token[:i])
	if err != nil {
		return nil, NotVaildErr
	}
	header = new(Header)
	err = json.Unmarshal(head, header)
	if err != nil || strings.ToUpper(header.NoChange) != "JWT" {
		return nil, NotVaildErr
	}
	token = token[i + 1:]
	i = strings.IndexByte(token, '.')
	if i < 0 {
		return nil, NotVaildErr
	}
	body, err = base64.RawURLEncoding.DecodeString(token[:i])
	if err != nil {
		return nil, NotVaildErr
	}
	err = json.Unmarshal(body, ptr)
	if err != nil {
		return nil, err
	}
	token = token[i + 1:]
	mac, err = base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return nil, NotVaildErr
	}
	if !validMAC(header.Signer, head, body, mac, key) {
		err = NotVerifiedErr; return
	}
	if header.IsExpired() {
		err = ExpiredErr; return
	}
	if !header.IsActivity() {
		err = NotBeforeErr; return
	}
	return
}

func calcMAC(typ SignType, head, body []byte, key []byte)(mac []byte){
	h := hmac.New(typ.Hasher(), key)
	h.Write(head)
	h.Write(([]byte)("."))
	h.Write(body)
	return h.Sum(nil)
}

func validMAC(typ SignType, head, body []byte, mac []byte, key []byte)(bool){
	return hmac.Equal(mac, calcMAC(typ, head, body, key))
}
