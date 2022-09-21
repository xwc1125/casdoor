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

package idp

import (
	"net/http"
	"strings"

	"golang.org/x/oauth2"
)

type UserInfo struct {
	Id          string
	Username    string
	DisplayName string
	UnionId     string
	Email       string
	AvatarUrl   string
}

type IdProvider interface {
	New(clientId string, clientSecret string, redirectUrl string, opts map[string]string) IdProvider
	SetHttpClient(client *http.Client)
	GetToken(code string) (*oauth2.Token, error)
	GetUserInfo(token *oauth2.Token) (*UserInfo, error)
}

var (
	idProviders = make(map[string]IdProvider, 0)
)

func init() {
	RegisterIdProvider("GitHub", &GithubIdProvider{})
	RegisterIdProvider("Google", &GoogleIdProvider{})
	RegisterIdProvider("QQ", &QqIdProvider{})
	RegisterIdProvider("WeChat", &WeChatIdProvider{})
	RegisterIdProvider("Facebook", &FacebookIdProvider{})
	RegisterIdProvider("DingTalk", &DingTalkIdProvider{})
	RegisterIdProvider("Weibo", &WeiBoIdProvider{})
	RegisterIdProvider("Gitee", &GiteeIdProvider{})
	RegisterIdProvider("LinkedIn", &LinkedInIdProvider{})
	RegisterIdProvider("WeCom-Internal", &WeComInternalIdProvider{})
	RegisterIdProvider("WeCom-Third-party", &WeComIdProvider{})
	RegisterIdProvider("Lark", &LarkIdProvider{})
	RegisterIdProvider("GitLab", &GitlabIdProvider{})
	RegisterIdProvider("Adfs", &AdfsIdProvider{})
	RegisterIdProvider("Baidu", &BaiduIdProvider{})
	RegisterIdProvider("Alipay", &AlipayIdProvider{})
	RegisterIdProvider("Custom", &CustomIdProvider{})
	RegisterIdProvider("Infoflow-Internal", &InfoflowInternalIdProvider{})
	RegisterIdProvider("Infoflow-Third-party", &InfoflowIdProvider{})
	RegisterIdProvider("Casdoor", &CasdoorIdProvider{})
	RegisterIdProvider("Okta", &OktaIdProvider{})
	RegisterIdProvider("Douyin", &DouyinIdProvider{})
	RegisterIdProvider("Bilibili", &BilibiliIdProvider{})

	RegisterIdProvider("Amazon", &GothIdProvider{ProviderType: "Amazon"})
	RegisterIdProvider("Apple", &GothIdProvider{ProviderType: "Apple"})
	RegisterIdProvider("AzureAD", &GothIdProvider{ProviderType: "AzureAD"})
	RegisterIdProvider("Bitbucket", &GothIdProvider{ProviderType: "Bitbucket"})
	RegisterIdProvider("DigitalOcean", &GothIdProvider{ProviderType: "DigitalOcean"})
	RegisterIdProvider("Discord", &GothIdProvider{ProviderType: "Discord"})
	RegisterIdProvider("Dropbox", &GothIdProvider{ProviderType: "Dropbox"})
	RegisterIdProvider("Facebook", &GothIdProvider{ProviderType: "Facebook"})
	RegisterIdProvider("Gitea", &GothIdProvider{ProviderType: "Gitea"})
	RegisterIdProvider("GitHub", &GothIdProvider{ProviderType: "GitHub"})
	RegisterIdProvider("GitLab", &GothIdProvider{ProviderType: "GitLab"})
	RegisterIdProvider("Google", &GothIdProvider{ProviderType: "Google"})
	RegisterIdProvider("Heroku", &GothIdProvider{ProviderType: "Heroku"})
	RegisterIdProvider("Instagram", &GothIdProvider{ProviderType: "Instagram"})
	RegisterIdProvider("Kakao", &GothIdProvider{ProviderType: "Kakao"})
	RegisterIdProvider("Linkedin", &GothIdProvider{ProviderType: "Linkedin"})
	RegisterIdProvider("Line", &GothIdProvider{ProviderType: "Line"})
	RegisterIdProvider("MicrosoftOnline", &GothIdProvider{ProviderType: "MicrosoftOnline"})
	RegisterIdProvider("Paypal", &GothIdProvider{ProviderType: "Paypal"})
	RegisterIdProvider("SalesForce", &GothIdProvider{ProviderType: "SalesForce"})
	RegisterIdProvider("Shopify", &GothIdProvider{ProviderType: "Shopify"})
	RegisterIdProvider("Slack", &GothIdProvider{ProviderType: "Slack"})
	RegisterIdProvider("Steam", &GothIdProvider{ProviderType: "Steam"})
	RegisterIdProvider("Tumblr", &GothIdProvider{ProviderType: "Tumblr"})
	RegisterIdProvider("Twitter", &GothIdProvider{ProviderType: "Twitter"})
	RegisterIdProvider("Yahoo", &GothIdProvider{ProviderType: "Yahoo"})
	RegisterIdProvider("Yandex", &GothIdProvider{ProviderType: "Yandex"})
	RegisterIdProvider("Zoom", &GothIdProvider{ProviderType: "Zoom"})

}

func RegisterIdProvider(paymentType string, provider IdProvider) {
	idProviders[paymentType] = provider
}

func GetIdProvider(typ string, subType string, clientId string, clientSecret string, appId string, redirectUrl string, hostUrl string, authUrl string, tokenUrl string, userInfoUrl string) IdProvider {
	if len(subType) > 0 {
		typ = typ + "-" + subType
	}
	provider, ok := idProviders[typ]
	if !ok {
		return nil
	}

	opts := make(map[string]string)
	opts["hostUrl"] = hostUrl
	opts["authUrl"] = authUrl
	opts["tokenUrl"] = tokenUrl
	opts["userInfoUrl"] = userInfoUrl
	opts["appId"] = appId

	return provider.New(clientId, clientSecret, redirectUrl, opts)
}

var gothList = []string{"Apple", "AzureAd", "Slack", "Steam"}

func isGothSupport(provider string) bool {
	for _, value := range gothList {
		if strings.EqualFold(value, provider) {
			return true
		}
	}
	return false
}
