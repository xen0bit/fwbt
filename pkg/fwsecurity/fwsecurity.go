package fwsecurity

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"os"

	"github.com/dgrijalva/jwt-go"
	"github.com/schollz/progressbar/v3"
)

var FireresetPrivKey = `-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
`

func CheckSum(license string) string {
	h := sha256.New()
	h.Write([]byte(license[:8]))
	bs := h.Sum(nil)[:8]
	cs := base64.StdEncoding.EncodeToString(bs)
	return cs
}

func CrackCs(cs string) {
	h := sha256.New()
	testVal := make([]byte, 4)
	var hexTestVal string
	bar := progressbar.Default(4294967295)
	for i := uint32(0); i < 4294967295; i++ {
		h.Reset()
		binary.LittleEndian.PutUint32(testVal, i)
		//Already 8 chars
		hexTestVal = hex.EncodeToString(testVal)
		h.Write([]byte(hexTestVal))
		testSum := h.Sum(nil)[:8]
		b64TestSum := base64.StdEncoding.EncodeToString(testSum)
		if b64TestSum == cs {
			break
		}
		bar.Add(1)
	}
	bar.Finish()
	fmt.Println("Solved License Prefix:", hexTestVal)
}

func FindCs(cs string) string {
	// first open the file
	file, err := os.Open("rainbow.csv")
	if err != nil {
		log.Fatalf("could not open the file: %v", err)
	}
	// don't forget to close the file.
	defer file.Close()
	// finally, we can have our scanner
	scanner := bufio.NewScanner(file)

	bcs := []byte(cs)
	var rLine string
	bar := progressbar.Default(4294967295)
	for {
		if scanner.Scan() {
			if bline := scanner.Bytes(); bytes.Contains(bline, bcs) {
				rLine = string(bline)
				break
			}
			bar.Add(1)
		}
	}
	bar.Finish()
	return rLine
}

// jwt

func SignLicense(license string) string {
	pk, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(FireresetPrivKey))
	if err != nil {
		panic(err)
	}
	//fmt.Println(pk.PublicKey)
	claims := make(jwt.MapClaims)
	claims["license"] = license
	a := jwt.New(jwt.SigningMethodRS256)
	a.Claims = claims
	delete(a.Header, "typ")
	ss, _ := a.SignedString(pk)
	return ss
}
