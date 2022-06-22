
package jwt

import (
	"hash"
	"crypto/sha256"
	"crypto/sha512"
	"strings"
	"time"
)

type hasherFunc = func()(hash.Hash)

type SignType string
const (
	SignHS512     SignType = "HS512"
	SignHS384     SignType = "HS384"
	SignHS512_256 SignType = "HS512/256"
	SignHS512_224 SignType = "HS512/224"
	SignHS256     SignType = "HS256"
	SignHS224     SignType = "HS224"
)

func (s SignType)Hasher()(hasherFunc){
	switch (SignType)(strings.ToUpper((string)(s))) {
	case SignHS512: return sha512.New
	case SignHS384: return sha512.New384
	case SignHS512_256: return sha512.New512_256
	case SignHS512_224: return sha512.New512_224
	case SignHS256: return sha256.New
	case SignHS224: return sha256.New224
	}
	panic("Unknown signtype: " + (string)(s))
}

type Header struct{
	NoChange string       `json:"typ"`
	Signer SignType       `json:"alg"`
	IssuedAt time.Time    `json:"isa"`
	Id string             `json:"jti,omitempty"`
	Expiration *time.Time `json:"exp,omitempty"`
	NotBefore *time.Time  `json:"nbf,omitempty"`
	Issuer string         `json:"iss,omitempty"`
	Audience string       `json:"aud,omitempty"`
	Subject string        `json:"sub,omitempty"`
	Extra interface{}     `json:"ext,omitempty"`
}

func NewHeader()(h *Header){
	return &Header{
		NoChange: "JWT",
		Signer: SignHS256,
	}
}

func (h *Header)SetSigner(s SignType)(*Header){
	h.Signer = s
	return h
}

func (h *Header)SetId(id string)(*Header){
	h.Id = id
	return h
}

func (h *Header)SetExpiration(t time.Time)(*Header){
	h.Expiration = &t
	return h
}

func (h *Header)IsExpired()(bool){
	return h.Expiration != nil && h.Expiration.Before(time.Now())
}

func (h *Header)Duration(t time.Duration)(*Header){
	h.SetExpiration(time.Now().Add(t))
	return h
}

func (h *Header)SetNotBefore(t time.Time)(*Header){
	h.NotBefore = &t
	return h
}

func (h *Header)IsActivity()(bool){
	return h.NotBefore == nil || h.NotBefore.After(time.Now())
}

func (h *Header)ActivateAfter(t time.Duration)(*Header){
	h.SetNotBefore(time.Now().Add(t))
	return h
}

func (h *Header)SetIssuer(v string)(*Header){
	h.Issuer = v
	return h
}

func (h *Header)SetAudience(v string)(*Header){
	h.Audience = v
	return h
}

func (h *Header)SetSubject(v string)(*Header){
	h.Subject = v
	return h
}

func (h *Header)SetExtra(v interface{})(*Header){
	h.Extra = v
	return h
}
