// Copyright © 2017 The Kubicorn Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package golinodeSdk

import (
	"fmt"
	"os"

	"github.com/chiefy/go-linode"
)

type Sdk struct {
	Client *golinode.Client
}

func NewSdk() (*Sdk, error) {
	sdk := &Sdk{}
	pat := GetToken()

	if pat == "" {
		return nil, fmt.Errorf("Empty $LINODE_ACCESS_TOKEN")
	}

	client, err := golinode.NewClient(&pat, nil)

	if err != nil {
		return nil, fmt.Errorf("Could not create Linode Client")
	}

	sdk.Client = client
	return sdk, nil
}

func GetToken() string {
	return os.Getenv("LINODE_ACCESS_TOKEN")
}
