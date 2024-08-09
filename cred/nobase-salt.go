package cred

import (
	"encoding/hex"
	"strconv"

	"golang.org/x/crypto/scrypt"
)

type NoBaseCredManager struct{}

func NewNoBaseCredManager() *NoBaseCredManager {
	cm := &NoBaseCredManager{}
	return cm
}

func (cm *NoBaseCredManager) GetHashedPassword(password string, userSalt string, organizationSalt string) string {
	// 无盐值时，使用随机盐值生成密码
	var decodedSalt []byte
	if userSalt == "" {
		decodedSalt, _ = generateSalt(8)
		userSalt = hex.EncodeToString(decodedSalt)
	}

	// https://www.keycloak.org/docs/latest/server_admin/index.html#password-database-compromised
	plainPasswordBytes, err := scrypt.Key([]byte(password), []byte(userSalt), 16384, 8, 1, 24)
	if err != nil {
		return ""
	}

	newpass := userSalt + hex.EncodeToString(plainPasswordBytes)
	return newpass
}

func (cm *NoBaseCredManager) IsPasswordCorrect(plainPwd string, hashedPwd string, userSalt string, organizationSalt string) bool {
	// 切分密码盐值
	salt, err := strconv.Unquote(`"` + hashedPwd[:16] + `"`) // 确保是合法的UTF-8序列
	if err != nil {
		return false
	}
	newHashedPassword := cm.GetHashedPassword(plainPwd, salt, organizationSalt)

	return hashedPwd == newHashedPassword
}
