package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	jwt "github.com/dgrijalva/jwt-go"
)

func testAccessToken(uri, clientID, clientSecret string) {
	form := url.Values{
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"grant_type":    {"client_credentials"},
		"scope":         {"resource.readonly"},
	}
	response, err := http.Post(uri, "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		panic(err)
	}
	defer response.Body.Close()

	tokens, err := ioutil.ReadAll(response.Body)
	if err != nil {
		panic(err)
	}

	var tokensMap map[string]interface{}
	if err := json.Unmarshal(tokens, &tokensMap); err != nil {
		panic(err)
	}

	fmt.Println(tokensMap)
	accessToken := tokensMap["access_token"].(string)
	parseJWT(accessToken)
}

func parseJWT(tkn string) {
	token, err := jwt.Parse(tkn, func(t *jwt.Token) (interface{}, error) {
		kid := t.Header["kid"].(float64)
		ikid := int(kid)
		skid := strconv.Itoa(ikid)
		publicKey := getPublicKey(skid)
		return publicKey, nil
	})
	if err != nil {
		panic(err)
	}
	fmt.Println(token.Valid)
	fmt.Println("Header ", token.Header)
	fmt.Println("Claims ", token.Claims)
}

func getPublicKey(kid string) *rsa.PublicKey {
	response, err := http.Get("http://localhost:8080/api/secret/" + kid)
	if err != nil {
		panic(err)
	}
	defer response.Body.Close()

	strResp, err := ioutil.ReadAll(response.Body)
	if err != nil {
		panic(err)
	}

	var respMap map[string]interface{}
	if err := json.Unmarshal(strResp, &respMap); err != nil {
		panic(err)
	}

	publicKeyStr := respMap["public_key"].(string)
	keyBlock, _ := pem.Decode([]byte(publicKeyStr))
	if keyBlock == nil {
		panic("invalid key data")
	}
	if keyBlock.Type != "PUBLIC KEY" {
		panic("invalid key type " + keyBlock.Type)
	}

	publicKeyIF, err := x509.ParsePKIXPublicKey(keyBlock.Bytes)
	if err != nil {
		panic(err)
	}

	key := publicKeyIF.(*rsa.PublicKey)
	return key
}
