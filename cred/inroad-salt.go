// Copyright 2022 The Casdoor Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cred

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

type InroadSaltCredManager struct{}

func NewInroadSaltCredManager() *InroadSaltCredManager {
	cm := &InroadSaltCredManager{}
	return cm
}

func (cm *InroadSaltCredManager) GetHashedPassword(password string, userSalt string, organizationSalt string) string {
	// https://www.keycloak.org/docs/latest/server_admin/index.html#password-database-compromised
	//无盐值时，使用随机盐值生成密码
	var decodedSalt []byte
	if userSalt != "" {
		decodedSalt, _ = base64.StdEncoding.DecodeString(userSalt)
	} else {
		decodedSalt, _ = generateSalt(16)
	}

	plainPasswordBytes := pbkdf2.Key([]byte(password), decodedSalt, 1000, 32, sha1.New)

	// 创建一个足够大的数组来存储结果
	combinedBytes := make([]byte, 0, 49)

	// 0号元素
	bytes1 := [1]byte{1}
	combinedBytes = append(combinedBytes, bytes1[:]...)
	// 将第一个字节数组的内容复制到combinedBytes
	combinedBytes = append(combinedBytes, decodedSalt[:]...)
	// 将第二个字节数组的内容复制到combinedBytes
	combinedBytes = append(combinedBytes, plainPasswordBytes[:]...)

	return base64.StdEncoding.EncodeToString(combinedBytes)
}

func (cm *InroadSaltCredManager) IsPasswordCorrect(plainPwd string, hashedPwd string, userSalt string, organizationSalt string) bool {
	// 使用base64.StdEncoding解码
	decodedBytes, err := base64.StdEncoding.DecodeString(hashedPwd)
	saltBytes := decodedBytes[1:17]

	if err != nil {
		return false
	}

	return hashedPwd == cm.GetHashedPassword(plainPwd, base64.StdEncoding.EncodeToString(saltBytes), organizationSalt)
}

// 生成指定长度的随机盐值
func generateSalt(length int) ([]byte, error) {
	// 创建一个长度为`length`的字节切片
	salt := make([]byte, length)
	// 用加密安全的随机数填充字节切片
	_, err := io.ReadFull(rand.Reader, salt)
	if err != nil {
		return nil, err
	}
	return salt, nil
}
