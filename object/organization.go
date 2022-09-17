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

	"github.com/casdoor/casdoor/cred"
	"github.com/casdoor/casdoor/util"
	"xorm.io/core"
)

// AccountItem 个人页设置项
type AccountItem struct {
	Name       string `json:"name" comment:"名称"`
	Visible    bool   `json:"visible" comment:"是否可见"`
	ViewRule   string `json:"viewRule" comment:"查看规则"`   // Public/Self/Admin
	ModifyRule string `json:"modifyRule" comment:"修改规则"` // Admin/Self/Immutable
}

// Organization 组织
type Organization struct {
	Owner       string `xorm:"varchar(100) notnull pk" json:"owner" comment:"owner"`
	Name        string `xorm:"varchar(100) notnull pk" json:"name" comment:"名称"`
	CreatedTime string `xorm:"varchar(100)" json:"createdTime" comment:"创建时间"`

	DisplayName        string   `xorm:"varchar(100)" json:"displayName" comment:"显示的名称"`
	WebsiteUrl         string   `xorm:"varchar(100)" json:"websiteUrl" comment:"网页地址"`
	Favicon            string   `xorm:"varchar(100)" json:"favicon" comment:"网站图标"`
	PasswordType       string   `xorm:"varchar(100)" json:"passwordType" comment:"密码类型"`
	PasswordSalt       string   `xorm:"varchar(100)" json:"passwordSalt" comment:"密码Salt值"`
	PhonePrefix        string   `xorm:"varchar(10)"  json:"phonePrefix" comment:"手机号前缀"`
	DefaultAvatar      string   `xorm:"varchar(100)" json:"defaultAvatar" comment:"默认头像"`
	Tags               []string `xorm:"mediumtext" json:"tags" comment:"标签集合"`
	MasterPassword     string   `xorm:"varchar(100)" json:"masterPassword" comment:"万能密码"`
	EnableSoftDeletion bool     `json:"enableSoftDeletion" comment:"软删除"`
	IsProfilePublic    bool     `json:"isProfilePublic" comment:"是否用户个人页公开"`

	AccountItems []*AccountItem `xorm:"varchar(3000)" json:"accountItems" comment:"个人页设置项"`
}

func GetOrganizationCount(owner, field, value string) int {
	session := GetSession(owner, -1, -1, field, value, "", "")
	count, err := session.Count(&Organization{})
	if err != nil {
		panic(err)
	}

	return int(count)
}

func GetOrganizations(owner string) []*Organization {
	organizations := []*Organization{}
	err := adapter.Engine.Desc("created_time").Find(&organizations, &Organization{Owner: owner})
	if err != nil {
		panic(err)
	}

	return organizations
}

func GetPaginationOrganizations(owner string, offset, limit int, field, value, sortField, sortOrder string) []*Organization {
	organizations := []*Organization{}
	session := GetSession(owner, offset, limit, field, value, sortField, sortOrder)
	err := session.Find(&organizations)
	if err != nil {
		panic(err)
	}

	return organizations
}

func getOrganization(owner string, name string) *Organization {
	if owner == "" || name == "" {
		return nil
	}

	organization := Organization{Owner: owner, Name: name}
	existed, err := adapter.Engine.Get(&organization)
	if err != nil {
		panic(err)
	}

	if existed {
		return &organization
	}

	return nil
}

func GetOrganization(id string) *Organization {
	owner, name := util.GetOwnerAndNameFromId(id)
	return getOrganization(owner, name)
}

func GetMaskedOrganization(organization *Organization) *Organization {
	if organization == nil {
		return nil
	}

	if organization.MasterPassword != "" {
		organization.MasterPassword = "***"
	}
	return organization
}

func GetMaskedOrganizations(organizations []*Organization) []*Organization {
	for _, organization := range organizations {
		organization = GetMaskedOrganization(organization)
	}
	return organizations
}

func UpdateOrganization(id string, organization *Organization) bool {
	owner, name := util.GetOwnerAndNameFromId(id)
	if getOrganization(owner, name) == nil {
		return false
	}

	if name == "built-in" {
		organization.Name = name
	}

	if name != organization.Name {
		go func() {
			application := new(Application)
			application.Organization = organization.Name
			_, _ = adapter.Engine.Where("organization=?", name).Update(application)

			user := new(User)
			user.Owner = organization.Name
			_, _ = adapter.Engine.Where("owner=?", name).Update(user)
		}()
	}

	if organization.MasterPassword != "" && organization.MasterPassword != "***" {
		credManager := cred.GetCredManager(organization.PasswordType)
		if credManager != nil {
			hashedPassword := credManager.GetHashedPassword(organization.MasterPassword, "", organization.PasswordSalt)
			organization.MasterPassword = hashedPassword
		}
	}

	session := adapter.Engine.ID(core.PK{owner, name}).AllCols()
	if organization.MasterPassword == "***" {
		session.Omit("master_password")
	}
	affected, err := session.Update(organization)
	if err != nil {
		panic(err)
	}

	return affected != 0
}

func AddOrganization(organization *Organization) bool {
	affected, err := adapter.Engine.Insert(organization)
	if err != nil {
		panic(err)
	}

	return affected != 0
}

func DeleteOrganization(organization *Organization) bool {
	if organization.Name == "built-in" {
		return false
	}

	affected, err := adapter.Engine.ID(core.PK{organization.Owner, organization.Name}).Delete(&Organization{})
	if err != nil {
		panic(err)
	}

	return affected != 0
}

func GetOrganizationByUser(user *User) *Organization {
	return getOrganization("admin", user.Owner)
}

func GetAccountItemByName(name string, organization *Organization) *AccountItem {
	if organization == nil {
		return nil
	}
	for _, accountItem := range organization.AccountItems {
		if accountItem.Name == name {
			return accountItem
		}
	}
	return nil
}

func CheckAccountItemModifyRule(accountItem *AccountItem, user *User) (bool, string) {
	switch accountItem.ModifyRule {
	case "Admin":
		if !(user.IsAdmin || user.IsGlobalAdmin) {
			return false, fmt.Sprintf("Only admin can modify the %s.", accountItem.Name)
		}
	case "Immutable":
		return false, fmt.Sprintf("The %s is immutable.", accountItem.Name)
	case "Self":
		break
	default:
		return false, fmt.Sprintf("Unknown modify rule %s.", accountItem.ModifyRule)
	}
	return true, ""
}

func GetDefaultApplication(id string) *Application {
	organization := GetOrganization(id)
	if organization == nil {
		return nil
	}

	if organization.DefaultApplication != "" {
		return getApplication("admin", organization.DefaultApplication)
	}

	applications := []*Application{}
	err := adapter.Engine.Asc("created_time").Find(&applications, &Application{Organization: organization.Name})
	if err != nil {
		panic(err)
	}

	if len(applications) == 0 {
		return nil
	}

	defaultApplication := applications[0]
	for _, application := range applications {
		if application.EnableSignUp {
			defaultApplication = application
			break
		}
	}

	extendApplicationWithProviders(defaultApplication)
	extendApplicationWithOrg(defaultApplication)

	return defaultApplication
}
