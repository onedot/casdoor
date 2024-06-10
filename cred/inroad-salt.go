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
	"crypto/sha1"
	"encoding/base64"

	"golang.org/x/crypto/pbkdf2"
)

type InroadSaltCredManager struct{}

func NewInroadSaltCredManager() *InroadSaltCredManager {
	cm := &InroadSaltCredManager{}
	return cm
}

func (cm *InroadSaltCredManager) GetHashedPassword(password string, userSalt string, organizationSalt string) string {
	// https://www.keycloak.org/docs/latest/server_admin/index.html#password-database-compromised
	decodedSalt, _ := base64.StdEncoding.DecodeString(userSalt)
	plainPasswordBytes := pbkdf2.Key([]byte(password), decodedSalt, 1000, 32, sha1.New)

	res := append(decodedSalt,plainPasswordBytes)
	return base64.StdEncoding.EncodeToString(res)
}

func (cm *InroadSaltCredManager) IsPasswordCorrect(plainPwd string, hashedPwd string, userSalt string, organizationSalt string) bool {

	// 使用base64.StdEncoding解码
        decodedBytes, err := base64.StdEncoding.DecodeString(hashedPwd)
	saltBytes := decodedBytes[1:17]
	passwordBytes:= decodedBytes[16:50]
	
	return hashedPwd == cm.GetHashedPassword(plainPwd, base64.StdEncoding.EncodeToString(saltBytes), organizationSalt)
}
