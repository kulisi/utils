package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
)

type SheinAESTools struct {
	blockLength int
	ivLength    int
}

func NewDefaultAESTools() *SheinAESTools {
	return &SheinAESTools{128, 16}
}
func (t SheinAESTools) Decrypt(content string, key string) ([]byte, error) {
	// content Base64(IV+AES密文)
	if content != "" && len(content) != 0 && key != "" && len(key) != 0 {
		// 对content 进行 base64 解密
		decode, err := base64.StdEncoding.DecodeString(content)
		if err != nil {
			return nil, err
		}
		// 验证 密文长度
		if len(decode) <= t.ivLength {
			return nil, errors.New("错误的密文")
		} else {
			var ivBytes = make([]byte, t.ivLength)
			var realDate = make([]byte, len(decode)-t.ivLength)
			ivBytes = decode[:t.ivLength]
			realDate = decode[t.ivLength:]
			return t.decrypt(realDate, []byte(key)[:t.ivLength], ivBytes)
		}
	} else {
		return nil, errors.New("密文和密钥不能为空")
	}
}

func (t SheinAESTools) DecryptString(content string, key string) (string, error) {
	// content Base64(IV+AES密文)
	if content != "" && len(content) != 0 && key != "" && len(key) != 0 {
		// 对content 进行 base64 解密
		decode, err := base64.StdEncoding.DecodeString(content)
		if err != nil {
			return "", err
		}
		// 验证 密文长度
		if len(decode) <= t.ivLength {
			return "", errors.New("错误的密文")
		} else {
			var ivBytes = make([]byte, t.ivLength)
			var realDate = make([]byte, len(decode)-t.ivLength)
			ivBytes = decode[:t.ivLength]
			realDate = decode[t.ivLength:]
			b, err := t.decrypt(realDate, []byte(key)[:t.ivLength], ivBytes)
			return string(b), err
		}
	} else {
		return "", errors.New("密文和密钥不能为空")
	}
}

func (t SheinAESTools) decrypt(content, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	result := make([]byte, len(content))
	mode.CryptBlocks(result, content)
	result = t.pkcs5UnPadding(result)
	return result, nil
}

func (t SheinAESTools) pkcs5UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}
