/*
Copyright 2020 Howard Liu

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package openid

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// This prime number is encoded in Hex
const DefaultPrimeEncoded = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF"
const DefaultGroup = 2

// This is the MAC key
var associationKey []byte
var associationHandle string
var associationExpiresIn int64

// If this is set to true, we will verify the callback with the OP server
// even local verification is passed in association mode
var doubleVerification bool

func checkAssociation(opEndpoint string) {
	if time.Now().Unix() >= associationExpiresIn || associationHandle == "" {
		associateOp(opEndpoint)
	}
}

func associateOp(opEndpoint string) {
	values := make(url.Values)
	values.Add("openid.ns", "http://specs.openid.net/auth/2.0")
	values.Add("openid.mode", "associate")
	values.Add("openid.assoc_type", "HMAC-SHA256")
	values.Add("openid.session_type", "DH-SHA256")

	// Generate key
	xaSlice := make([]byte, 32)
	_, err := rand.Read(xaSlice)
	if err != nil {
		// handle error here
	}
	xa := new(big.Int).SetBytes(xaSlice)

	p, _ := new(big.Int).SetString(DefaultPrimeEncoded, 16)
	g := big.NewInt(DefaultGroup)
	// A = g ^ xa mod p
	A := new(big.Int).Exp(g, xa, p)

	values.Add("openid.dh_modulus", btwocEncode(p))
	values.Add("openid.dh_gen", btwocEncode(g))
	values.Add("openid.dh_consumer_public", btwocEncode(A))
	if resp, err := defaultInstance.urlGetter.Post(opEndpoint, values); err == nil {
		defer resp.Body.Close()
		content, _ := ioutil.ReadAll(resp.Body)
		response := string(content)
		lines := strings.Split(response, "\n")
		parameters := make(map[string]string)
		for _, line := range lines {
			if line != "" {
				tags := strings.Split(line, ":")
				parameters[tags[0]] = tags[1]
			}
		}
		if parameters["error"] != "" {
			// handle error here
		} else {
			BSlice, _ := btwocDecode(parameters["dh_server_public"])
			B := new(big.Int).SetBytes(BSlice)
			// This is the shared secret between us and the OP server
			// secret = B ^ xa mod p = (g ^ xa) ^ xb mod p
			secret := new(big.Int).Exp(B, xa, p)
			secretSlice := btwoc(secret)
			h := sha256.New()
			h.Write(secretSlice)
			secretHashed := h.Sum(nil)
			encryptedKey, _ := btwocDecode(parameters["enc_mac_key"])
			associationKey = make([]byte, 32)
			for k := range encryptedKey {
				associationKey[k] = encryptedKey[k] ^ secretHashed[k]
			}
			associationHandle = parameters["assoc_handle"]
			// a 30-second allowance is given to avoid problems caused by network delay
			expiresIn, _ := strconv.Atoi(parameters["expires_in"])
			associationExpiresIn = time.Now().Unix() + int64(expiresIn) - 30
			log.Println("OP associated: assoc_handle=" + associationHandle)
		}
	} else {
		log.Print(err)
		// handle error here
	}
}

// This is equivalent of the base64(btwoc(number)) specified in OpenID Specification 2.0
func btwocEncode(number *big.Int) string {
	return base64.StdEncoding.EncodeToString(btwoc(number))
}

func btwoc(number *big.Int) (byteSlice []byte) {
	byteSlice = number.Bytes()
	if byteSlice[0] >= 0x80 {
		// For btwoc, the highest bit must be 0. If not, we append a \x00
		byteSlice = append([]byte{0x00}, byteSlice...)
	}
	return
}

func btwocDecode(data string) (dataSlice []byte, err error) {
	if dataSlice, err = base64.StdEncoding.DecodeString(data); err != nil {
		return
	} else {
		if dataSlice[0] == 0x00 {
			// Remove placeholder for the first \x00 byte
			dataSlice = dataSlice[1:]
		}
		return
	}
}

func hmacSign(data string) []byte {
	h := hmac.New(sha256.New, associationKey)
	io.WriteString(h, data)
	return h.Sum(nil)
}
