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
	"os"
	"testing"
)

var (
	LinodeAccessToken = os.Getenv("LINODE_TOKEN")
)

func TestMain(m *testing.M) {
	m.Run()
	os.Setenv("LINODE_TOKEN", LinodeAccessToken)
}

func TestSdkHappy(t *testing.T) {
	os.Setenv("LINODE_TOKEN", "123")
	_, err := NewSdk()
	if err != nil {
		t.Fatalf("Unable to get Linode SDK: %v", err)
	}
}

func TestSdkSad(t *testing.T) {
	os.Setenv("LINODE_TOKEN", "")
	_, err := NewSdk()
	if err == nil {
		t.Fatalf("Able to get Linode SDK with empty variables")
	}
}
