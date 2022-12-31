package util

import (
	"bytes"
	"encoding/base64"
	"errors"
	"math/rand"
)

func BytesCombine(pBytes ...[]byte) []byte {
	return bytes.Join(pBytes, []byte(""))
}

func XOR(text []byte, key []byte) []byte {
	for i := 0; i < len(text); i++ {
		text[i] = text[i] ^ key[i%len(key)]
	}
	return text
}

func NetbiosEncode(data []byte, key byte) []byte {
	var result []byte
	for _, value := range data {
		buf := make([]byte, 2)
		buf[0] = (value >> 4) + key
		buf[1] = value&0xf + key
		result = append(result, buf...)
	}
	return result
}

func NetbiosDecode(data []byte, key byte) []byte {
	var result []byte
	for i := 0; i < len(data); i += 2 {
		result = append(result, (data[i]-key)<<4+(data[i+1]-key)&0xf)
	}
	return result
}

// ALL USE BYTE!!!

// encrypt should not trigger error, this function does not modify input data
// encode/decode deployment can be found at c2profile.Program
func EncryptField(encryptTypes []string, data []byte) []byte {
	// make a copy of data
	result := make([]byte, len(data))
	copy(result, data)
	for _, encryptType := range encryptTypes {
		originData := result
		switch encryptType {
		case "base64":
			result = make([]byte, base64.StdEncoding.EncodedLen(len(originData)))
			base64.StdEncoding.Encode(result, originData)
		case "base64url":
			result = make([]byte, base64.RawURLEncoding.EncodedLen(len(originData)))
			base64.RawURLEncoding.Encode(result, originData)
		case "mask":
			// generate 4 random bytes to encrypt
			key := make([]byte, 4)
			result = make([]byte, len(originData))
			rand.Read(key)
			result = append(key, XOR(originData, key)...)
		case "netbios":
			result = NetbiosEncode(originData, byte('a'))
		// do nothing if no encrypt type given
		case "netbiosu":
			result = NetbiosEncode(originData, byte('A'))
		case "":
			break
		default:
			panic("not support for encode type " + encryptType)
		}
	}

	return result
}

// DecryptField decode data with reversed decryptTypes
func DecryptField(decryptTypes []string, data []byte) ([]byte, error) {
	for i := len(decryptTypes) - 1; i > -1; i-- {
		decryptType := decryptTypes[i]
		originData := data
		switch decryptType {
		case "base64":
			data = make([]byte, base64.StdEncoding.DecodedLen(len(originData)))
			_, err := base64.StdEncoding.Decode(data, originData)
			// decrypt error means get server command failed
			if err != nil {
				return nil, err
			}
		case "base64url":
			data = make([]byte, base64.RawURLEncoding.DecodedLen(len(originData)))
			_, err := base64.RawURLEncoding.Decode(data, originData)
			if err != nil {
				return nil, err
			}
		case "mask":
			// use first 4 bytes XOR payload
			if len(data) > 4 {
				key := data[0:4]
				data = data[4:]
				data = XOR(data, key)
			} else {
				return nil, errors.New("invalid mask length")
			}
		case "netbios":
			data = NetbiosDecode(originData, 'a')
		case "netbiosu":
			data = NetbiosDecode(originData, 'A')
		// do nothing if no decrypt type given
		case "":
			break
		default:
			panic("not support for encode type " + decryptType)
		}
	}
	return data, nil
}
