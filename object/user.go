// Copyright 2021 The Casdoor Authors. All Rights Reserved.
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

package object

import (
	"fmt"
	"strings"

	"github.com/casdoor/casdoor/conf"
	"github.com/casdoor/casdoor/util"
	"github.com/duo-labs/webauthn/webauthn"
	"xorm.io/core"
)

const (
	UserPropertiesWechatUnionId = "wechatUnionId"
	UserPropertiesWechatOpenId  = "wechatOpenId"
)

// User 用户信息
type User struct {
	Owner       string `xorm:"varchar(100) notnull pk" json:"owner" comment:"组织"`
	Name        string `xorm:"varchar(100) notnull pk" json:"name" comment:"用户名称"`
	CreatedTime string `xorm:"varchar(100)" json:"createdTime" comment:"创建时间"`
	UpdatedTime string `xorm:"varchar(100)" json:"updatedTime" comment:"更新时间"`

	Id                string   `xorm:"varchar(100) index" json:"id" comment:"用户ID"`
	Type              string   `xorm:"varchar(100)" json:"type" comment:"用户类型"` // normal-user
	Password          string   `xorm:"varchar(100)" json:"password" comment:"密码"`
	PasswordSalt      string   `xorm:"varchar(100)" json:"passwordSalt" comment:"密码加盐"`
	DisplayName       string   `xorm:"varchar(100)" json:"displayName" comment:"显示名称"`
	FirstName         string   `xorm:"varchar(100)" json:"firstName" comment:"名字"`
	LastName          string   `xorm:"varchar(100)" json:"lastName" comment:"姓"`
	Avatar            string   `xorm:"varchar(500)" json:"avatar" comment:"头像"`
	PermanentAvatar   string   `xorm:"varchar(500)" json:"permanentAvatar" comment:"持久头像"`
	Email             string   `xorm:"varchar(100) index" json:"email" comment:"电子邮箱"`
	EmailVerified     bool     `json:"emailVerified" comment:"邮箱是否验证"`
	Phone             string   `xorm:"varchar(100) index" json:"phone" comment:"手机号"`
	Location          string   `xorm:"varchar(100)" json:"location" comment:"城市"`
	Address           []string `json:"address" comment:"地址"`
	Affiliation       string   `xorm:"varchar(100)" json:"affiliation" comment:"工作单位"`
	Title             string   `xorm:"varchar(100)" json:"title" comment:"职务"`
	IdCardType        string   `xorm:"varchar(100)" json:"身份类型"`
	IdCard            string   `xorm:"varchar(100) index" json:"身份证号"`
	Homepage          string   `xorm:"varchar(100)" json:"个人主页"`
	Bio               string   `xorm:"varchar(100)" json:"自我介绍"`
	Tag               string   `xorm:"varchar(100)" json:"标签"`
	Region            string   `xorm:"varchar(100)" json:"国家/地区"`
	Language          string   `xorm:"varchar(100)" json:"语言"`
	Gender            string   `xorm:"varchar(100)" json:"性别"`
	Birthday          string   `xorm:"varchar(100)" json:"生日"`
	Education         string   `xorm:"varchar(100)" json:"教育"`
	Score             int      `json:"score" comment:"分数"`
	Karma             int      `json:"karma" comment:"Karma"`
	Ranking           int      `json:"ranking" comment:"排名"`
	IsDefaultAvatar   bool     `json:"isDefaultAvatar" comment:"是否默认头像"`
	IsOnline          bool     `json:"isOnline" comment:"是否在线"`
	IsAdmin           bool     `json:"isAdmin" comment:"是管理员"`
	IsGlobalAdmin     bool     `json:"isGlobalAdmin" comment:"是全局管理员"`
	IsForbidden       bool     `json:"isForbidden" comment:"被禁用"`
	IsDeleted         bool     `json:"isDeleted" comment:"被删除"`
	SignupApplication string   `xorm:"varchar(100)" json:"signupApplication" comment:"注册应用"`
	Hash              string   `xorm:"varchar(100)" json:"hash" comment:"Hash"`
	PreHash           string   `xorm:"varchar(100)" json:"preHash" comment:"PreHash"`

	CreatedIp      string `xorm:"varchar(100)" json:"createdIp" comment:"创建的IP"`
	LastSigninTime string `xorm:"varchar(100)" json:"lastSigninTime" comment:"最近登录时间"`
	LastSigninIp   string `xorm:"varchar(100)" json:"lastSigninIp" comment:"最近登录IP"`

	GitHub   string `xorm:"github varchar(100)" json:"github"`
	Google   string `xorm:"varchar(100)" json:"google"`
	QQ       string `xorm:"qq varchar(100)" json:"qq"`
	WeChat   string `xorm:"wechat varchar(100)" json:"wechat"`
	Facebook string `xorm:"facebook varchar(100)" json:"facebook"`
	DingTalk string `xorm:"dingtalk varchar(100)" json:"dingtalk"`
	Weibo    string `xorm:"weibo varchar(100)" json:"weibo"`
	Gitee    string `xorm:"gitee varchar(100)" json:"gitee"`
	LinkedIn string `xorm:"linkedin varchar(100)" json:"linkedin"`
	Wecom    string `xorm:"wecom varchar(100)" json:"wecom"`
	Lark     string `xorm:"lark varchar(100)" json:"lark"`
	Gitlab   string `xorm:"gitlab varchar(100)" json:"gitlab"`
	Adfs     string `xorm:"adfs varchar(100)" json:"adfs"`
	Baidu    string `xorm:"baidu varchar(100)" json:"baidu"`
	Alipay   string `xorm:"alipay varchar(100)" json:"alipay"`
	Casdoor  string `xorm:"casdoor varchar(100)" json:"casdoor"`
	Infoflow string `xorm:"infoflow varchar(100)" json:"infoflow"`
	Apple    string `xorm:"apple varchar(100)" json:"apple"`
	AzureAD  string `xorm:"azuread varchar(100)" json:"azuread"`
	Slack    string `xorm:"slack varchar(100)" json:"slack"`
	Steam    string `xorm:"steam varchar(100)" json:"steam"`
	Bilibili string `xorm:"bilibili varchar(100)" json:"bilibili"`
	Okta     string `xorm:"okta varchar(100)" json:"okta"`
	Douyin   string `xorm:"douyin varchar(100)" json:"douyin"`
	Custom   string `xorm:"custom varchar(100)" json:"custom"`

	WebauthnCredentials []webauthn.Credential `xorm:"webauthnCredentials blob" json:"webauthnCredentials"`

	Ldap       string            `xorm:"ldap varchar(100)" json:"ldap"`
	Properties map[string]string `json:"properties"`

	Roles       []*Role       `json:"roles"`
	Permissions []*Permission `json:"permissions"`

	LastSigninWrongTime string `xorm:"varchar(100)" json:"lastSigninWrongTime" comment:"最近登录出错时间"`
	SigninWrongTimes    int    `json:"signinWrongTimes" comment:"登录出错次数"`

	ManagedAccounts []ManagedAccount `xorm:"managedAccounts blob" json:"managedAccounts" comment:"托管账户"`
}

type Userinfo struct {
	Sub         string `json:"sub"`
	Iss         string `json:"iss"`
	Aud         string `json:"aud"`
	Name        string `json:"name,omitempty"`
	DisplayName string `json:"preferred_username,omitempty"`
	Email       string `json:"email,omitempty"`
	Avatar      string `json:"picture,omitempty"`
	Address     string `json:"address,omitempty"`
	Phone       string `json:"phone,omitempty"`
}

type ManagedAccount struct {
	Application string `xorm:"varchar(100)" json:"application"`
	Username    string `xorm:"varchar(100)" json:"username"`
	Password    string `xorm:"varchar(100)" json:"password"`
	SigninUrl   string `xorm:"varchar(200)" json:"signinUrl"`
}

func GetGlobalUserCount(field, value string) int {
	session := GetSession("", -1, -1, field, value, "", "")
	count, err := session.Count(&User{})
	if err != nil {
		panic(err)
	}

	return int(count)
}

func GetGlobalUsers() []*User {
	users := []*User{}
	err := adapter.Engine.Desc("created_time").Find(&users)
	if err != nil {
		panic(err)
	}

	return users
}

func GetPaginationGlobalUsers(offset, limit int, field, value, sortField, sortOrder string) []*User {
	users := []*User{}
	session := GetSession("", offset, limit, field, value, sortField, sortOrder)
	err := session.Find(&users)
	if err != nil {
		panic(err)
	}

	return users
}

func GetUserCount(owner, field, value string) int {
	session := GetSession(owner, -1, -1, field, value, "", "")
	count, err := session.Count(&User{})
	if err != nil {
		panic(err)
	}

	return int(count)
}

func GetOnlineUserCount(owner string, isOnline int) int {
	count, err := adapter.Engine.Where("is_online = ?", isOnline).Count(&User{Owner: owner})
	if err != nil {
		panic(err)
	}

	return int(count)
}

func GetUsers(owner string) []*User {
	users := []*User{}
	err := adapter.Engine.Desc("created_time").Find(&users, &User{Owner: owner})
	if err != nil {
		panic(err)
	}

	return users
}

func GetSortedUsers(owner string, sorter string, limit int) []*User {
	users := []*User{}
	err := adapter.Engine.Desc(sorter).Limit(limit, 0).Find(&users, &User{Owner: owner})
	if err != nil {
		panic(err)
	}

	return users
}

func GetPaginationUsers(owner string, offset, limit int, field, value, sortField, sortOrder string) []*User {
	users := []*User{}
	session := GetSession(owner, offset, limit, field, value, sortField, sortOrder)
	err := session.Find(&users)
	if err != nil {
		panic(err)
	}

	return users
}

func getUser(owner string, name string) *User {
	if owner == "" || name == "" {
		return nil
	}

	user := User{Owner: owner, Name: name}
	existed, err := adapter.Engine.Get(&user)
	if err != nil {
		panic(err)
	}

	if existed {
		return &user
	} else {
		return nil
	}
}

func getUserById(owner string, id string) *User {
	if owner == "" || id == "" {
		return nil
	}

	user := User{Owner: owner, Id: id}
	existed, err := adapter.Engine.Get(&user)
	if err != nil {
		panic(err)
	}

	if existed {
		return &user
	} else {
		return nil
	}
}

func getUserByWechatId(wechatOpenId string, wechatUnionId string) *User {
	if wechatUnionId == "" {
		wechatUnionId = wechatOpenId
	}
	user := &User{}
	existed, err := adapter.Engine.Where("wechat = ? OR wechat = ?", wechatOpenId, wechatUnionId).Get(user)
	if err != nil {
		panic(err)
	}

	if existed {
		return user
	} else {
		return nil
	}
}

func GetUserByEmail(owner string, email string) *User {
	if owner == "" || email == "" {
		return nil
	}

	user := User{Owner: owner, Email: email}
	existed, err := adapter.Engine.Get(&user)
	if err != nil {
		panic(err)
	}

	if existed {
		return &user
	} else {
		return nil
	}
}

func GetUserByPhone(owner string, phone string) *User {
	if owner == "" || phone == "" {
		return nil
	}

	user := User{Owner: owner, Phone: phone}
	existed, err := adapter.Engine.Get(&user)
	if err != nil {
		panic(err)
	}

	if existed {
		return &user
	} else {
		return nil
	}
}

func GetUserByUserId(owner string, userId string) *User {
	if owner == "" || userId == "" {
		return nil
	}

	user := User{Owner: owner, Id: userId}
	existed, err := adapter.Engine.Get(&user)
	if err != nil {
		panic(err)
	}

	if existed {
		return &user
	} else {
		return nil
	}
}

func GetUser(id string) *User {
	owner, name := util.GetOwnerAndNameFromId(id)
	return getUser(owner, name)
}

func GetUserNoCheck(id string) *User {
	owner, name := util.GetOwnerAndNameFromIdNoCheck(id)
	return getUser(owner, name)
}

func GetMaskedUser(user *User) *User {
	if user == nil {
		return nil
	}

	if user.Password != "" {
		user.Password = "***"
	}

	if user.ManagedAccounts != nil {
		for _, manageAccount := range user.ManagedAccounts {
			manageAccount.Password = "***"
		}
	}
	return user
}

func GetMaskedUsers(users []*User) []*User {
	for _, user := range users {
		user = GetMaskedUser(user)
	}
	return users
}

func GetLastUser(owner string) *User {
	user := User{Owner: owner}
	existed, err := adapter.Engine.Desc("created_time", "id").Get(&user)
	if err != nil {
		panic(err)
	}

	if existed {
		return &user
	}

	return nil
}

func UpdateUser(id string, user *User, columns []string, isGlobalAdmin bool) bool {
	owner, name := util.GetOwnerAndNameFromIdNoCheck(id)
	oldUser := getUser(owner, name)
	if oldUser == nil {
		return false
	}

	if user.Password == "***" {
		user.Password = oldUser.Password
	}
	user.UpdateUserHash()

	if user.Avatar != oldUser.Avatar && user.Avatar != "" && user.PermanentAvatar != "*" {
		user.PermanentAvatar = getPermanentAvatarUrl(user.Owner, user.Name, user.Avatar)
	}

	if len(columns) == 0 {
		columns = []string{
			"owner", "display_name", "avatar",
			"location", "address", "region", "language", "affiliation", "title", "homepage", "bio", "score", "tag", "signup_application",
			"is_admin", "is_global_admin", "is_forbidden", "is_deleted", "hash", "is_default_avatar", "properties", "webauthnCredentials", "managedAccounts",
			"signin_wrong_times", "last_signin_wrong_time",
		}
	}
	if isGlobalAdmin {
		columns = append(columns, "name", "email", "phone")
	}

	affected, err := adapter.Engine.ID(core.PK{owner, name}).Cols(columns...).Update(user)
	if err != nil {
		panic(err)
	}

	return affected != 0
}

func UpdateUserForAllFields(id string, user *User) bool {
	owner, name := util.GetOwnerAndNameFromId(id)
	oldUser := getUser(owner, name)
	if oldUser == nil {
		return false
	}

	user.UpdateUserHash()

	if user.Avatar != oldUser.Avatar && user.Avatar != "" {
		user.PermanentAvatar = getPermanentAvatarUrl(user.Owner, user.Name, user.Avatar)
	}

	affected, err := adapter.Engine.ID(core.PK{owner, name}).AllCols().Update(user)
	if err != nil {
		panic(err)
	}

	return affected != 0
}

func AddUser(user *User) bool {
	if user.Id == "" {
		user.Id = util.GenerateId()
	}

	if user.Owner == "" || user.Name == "" {
		return false
	}

	organization := GetOrganizationByUser(user)
	if organization == nil {
		return false
	}

	user.UpdateUserPassword(organization)

	user.UpdateUserHash()
	user.PreHash = user.Hash

	user.PermanentAvatar = getPermanentAvatarUrl(user.Owner, user.Name, user.Avatar)

	user.Ranking = GetUserCount(user.Owner, "", "") + 1

	affected, err := adapter.Engine.Insert(user)
	if err != nil {
		panic(err)
	}

	return affected != 0
}

func AddUsers(users []*User) bool {
	if len(users) == 0 {
		return false
	}

	// organization := GetOrganizationByUser(users[0])
	for _, user := range users {
		// this function is only used for syncer or batch upload, so no need to encrypt the password
		// user.UpdateUserPassword(organization)

		user.UpdateUserHash()
		user.PreHash = user.Hash

		user.PermanentAvatar = getPermanentAvatarUrl(user.Owner, user.Name, user.Avatar)
	}

	affected, err := adapter.Engine.Insert(users)
	if err != nil {
		if !strings.Contains(err.Error(), "Duplicate entry") {
			panic(err)
		}
	}

	return affected != 0
}

func AddUsersInBatch(users []*User) bool {
	batchSize := conf.GetConfigBatchSize()

	if len(users) == 0 {
		return false
	}

	affected := false
	for i := 0; i < (len(users)-1)/batchSize+1; i++ {
		start := i * batchSize
		end := (i + 1) * batchSize
		if end > len(users) {
			end = len(users)
		}

		tmp := users[start:end]
		// TODO: save to log instead of standard output
		// fmt.Printf("Add users: [%d - %d].\n", start, end)
		if AddUsers(tmp) {
			affected = true
		}
	}

	return affected
}

func DeleteUser(user *User) bool {
	affected, err := adapter.Engine.ID(core.PK{user.Owner, user.Name}).Delete(&User{})
	if err != nil {
		panic(err)
	}

	return affected != 0
}

func GetUserInfo(userId string, scope string, aud string, host string) (*Userinfo, error) {
	user := GetUser(userId)
	if user == nil {
		return nil, fmt.Errorf("the user: %s doesn't exist", userId)
	}

	_, originBackend := getOriginFromHost(host)

	resp := Userinfo{
		Sub: user.Id,
		Iss: originBackend,
		Aud: aud,
	}
	if strings.Contains(scope, "profile") {
		resp.Name = user.Name
		resp.DisplayName = user.DisplayName
		resp.Avatar = user.Avatar
	}
	if strings.Contains(scope, "email") {
		resp.Email = user.Email
	}
	if strings.Contains(scope, "address") {
		resp.Address = user.Location
	}
	if strings.Contains(scope, "phone") {
		resp.Phone = user.Phone
	}
	return &resp, nil
}

func LinkUserAccount(user *User, field string, value string) bool {
	return SetUserField(user, field, value)
}

func (user *User) GetId() string {
	return fmt.Sprintf("%s/%s", user.Owner, user.Name)
}

func isUserIdGlobalAdmin(userId string) bool {
	return strings.HasPrefix(userId, "built-in/")
}

func ExtendUserWithRolesAndPermissions(user *User) {
	if user == nil {
		return
	}

	user.Roles = GetRolesByUser(user.GetId())
	user.Permissions = GetPermissionsByUser(user.GetId())
}
