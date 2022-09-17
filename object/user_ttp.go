// Package object
//
// @author: xwc1125
package object

type UserTtp struct {
	UserId       string `xorm:"varchar(100) index" json:"user_id"`
	ProviderType string
	OAuthId      string
	Properties   string
}
