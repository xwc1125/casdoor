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

package captcha

type CaptchaProvider interface {
	VerifyCaptcha(token, clientSecret string) (bool, error)
}

var (
	captchaProviders = make(map[string]CaptchaProvider, 0)
)

func init() {
	RegisterCaptchaProvider("Aliyun Captcha", NewAliyunCaptchaProvider())
	RegisterCaptchaProvider("Default", NewDefaultCaptchaProvider())
	RegisterCaptchaProvider("GEETEST", NewGEETESTCaptchaProvider())
	RegisterCaptchaProvider("hCaptcha", NewHCaptchaProvider())
	RegisterCaptchaProvider("reCAPTCHA", NewReCaptchaProvider())
}

func RegisterCaptchaProvider(captchaType string, provider CaptchaProvider) {
	captchaProviders[captchaType] = provider
}

func GetCaptchaProvider(captchaType string) CaptchaProvider {
	provider, ok := captchaProviders[captchaType]
	if !ok {
		return nil
	}
	return provider
}
