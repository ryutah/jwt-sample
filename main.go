package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io/ioutil"
	"log"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

type User struct {
	Name string `json:"name"`
	Age  int    `json:"age"`
	jwt.StandardClaims
}

func main() {
	// 	createNewPemKey()
	// 	sampleJWT()
	testAccessToken("http://localhost:8080/api/access_token", "5733953138851840", "55b432673107efee9de110f49ab74234bbdc57592ae0cf4cccdcf61f68f29ab7")
}

func createNewPemKey() {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	savePEMKey := func(k *rsa.PrivateKey) {
		privateKey := &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		}
		bt := pem.EncodeToMemory(privateKey)
		log.Println(string(bt))
	}

	savePEMKey(key)
}

func DecodeHeader(jwtToken string) (string, error) {
	parts := strings.Split(jwtToken, ".")
	return DecodeURLSafeBase64(parts[0])
}

func DecodeClaims(jwtToken string) (string, error) {
	parts := strings.Split(jwtToken, ".")
	return DecodeURLSafeBase64(parts[1])
}

func DecodeURLSafeBase64(str string) (string, error) {
	if l := len(str) % 4; l > 0 {
		str += strings.Repeat("=", 4-l)
	}
	decodeStr, err := base64.URLEncoding.DecodeString(str)
	if err != nil {
		return "", err
	}
	return string(decodeStr), nil
}

func sampleJWT() {
	privateKey := readPrivateKey("private.key")
	tokenstring := createTokenString(privateKey)
	log.Println(tokenstring)

	header := strings.Split(tokenstring, ".")[0]
	if l := len(header) % 4; l > 0 {
		header += strings.Repeat("=", 4-l)
	}
	parseHeader, err := base64.URLEncoding.DecodeString(header)
	if err != nil {
		panic(err)
	}
	log.Println("Header : ", string(parseHeader))

	tkn, err := jwt.Parse(tokenstring, func(t *jwt.Token) (interface{}, error) {
		return readPublicKey("public.key"), nil
	})
	if err != nil {
		panic(err)
	}

	log.Println(tkn.Signature)
	log.Println(tkn.Header, tkn.Claims)

	user := User{}
	tkn, err = jwt.ParseWithClaims(tokenstring, &user, func(t *jwt.Token) (interface{}, error) {
		return readPublicKey("public.key"), nil
	})
	if err != nil {
		panic(err)
	}
	log.Println(tkn.Valid, user)
}

func readPrivateKey(path string) *rsa.PrivateKey {
	privateKeyFileData, err := ioutil.ReadFile(path)
	if err != nil {
		panic(err)
	}

	privateKeyBlock, _ := pem.Decode(privateKeyFileData)
	if privateKeyBlock == nil {
		panic("Invalid private key data")
	}
	if privateKeyBlock.Type != "RSA PRIVATE KEY" {
		panic("invalid key type : " + privateKeyBlock.Type)
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(privateKeyBlock.Bytes)
	if err != nil {
		panic(err)
	}
	return privateKey
}

func readPublicKey(path string) *rsa.PublicKey {
	publicKeyData, err := ioutil.ReadFile(path)
	if err != nil {
		panic(err)
	}
	publicKeyBlock, _ := pem.Decode(publicKeyData)
	if publicKeyBlock == nil {
		panic("invalid public key data")
	}
	if publicKeyBlock.Type != "PUBLIC KEY" {
		panic("invalid public key type : " + publicKeyBlock.Type)
	}

	publicKeyInterface, err := x509.ParsePKIXPublicKey(publicKeyBlock.Bytes)
	if err != nil {
		panic(err)
	}

	publicKey, ok := publicKeyInterface.(*rsa.PublicKey)
	if !ok {
		panic("not RSA public key")
	}
	return publicKey
}

func createTokenString(privateKey interface{}) string {
	usr := &User{
		Name: "Sample",
		Age:  30,
	}
	usr.Issuer = "hogehoge"
	usr.ExpiresAt = int64(15 * time.Minute)
	usr.IssuedAt = time.Now().Unix()
	tkn := jwt.NewWithClaims(jwt.SigningMethodRS256, usr)
	tkn.Header["kid"] = "hogehoge"
	tokenstring, err := tkn.SignedString(privateKey)
	if err != nil {
		panic(err)
	}
	return tokenstring
}
