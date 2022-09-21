// Package gparam
//
// @author: xwc1125
package gparam

import "fmt"

type GrantType string

const (
	GrantType_AuthorizationCode GrantType = "authorization_code"
	GrantType_Password          GrantType = "password"
	GrantType_ClientCredentials GrantType = "client_credentials"
	GrantType_RefreshToken      GrantType = "refresh_token"
)

func (t GrantType) String() string {
	return string(t)
}

func ParseGrantType(grantType string) (GrantType, error) {
	switch grantType {
	case GrantType_AuthorizationCode.String():
		return GrantType_AuthorizationCode, nil
	case GrantType_Password.String():
		return GrantType_Password, nil
	case GrantType_ClientCredentials.String():
		return GrantType_ClientCredentials, nil
	case GrantType_RefreshToken.String():
		return GrantType_RefreshToken, nil
	default:
		return "", fmt.Errorf("unsupport the grantType: %s", grantType)
	}
}
