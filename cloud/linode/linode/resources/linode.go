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

package resources

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/chiefy/go-linode"
	"github.com/kris-nova/klone/pkg/local"
	"github.com/kubicorn/kubicorn/apis/cluster"
	"github.com/kubicorn/kubicorn/cloud"
	"github.com/kubicorn/kubicorn/pkg/agent"
	"github.com/kubicorn/kubicorn/pkg/compare"
	"github.com/kubicorn/kubicorn/pkg/logger"
	"github.com/kubicorn/kubicorn/pkg/scp"
	"github.com/kubicorn/kubicorn/pkg/script"
)

var _ cloud.Resource = &Linode{}

type Linode struct {
	Shared
	Region           string
	Size             string
	Image            string
	Count            int
	SSHFingerprint   string
	BootstrapScripts []string
	ServerPool       *cluster.ServerPool
}

const (
	MasterIPAttempts               = 100
	MasterIPSleepSecondsPerAttempt = 5
	DeleteAttempts                 = 25
	DeleteSleepSecondsPerAttempt   = 3
)

func (r *Linode) Actual(immutable *cluster.Cluster) (*cluster.Cluster, cloud.Resource, error) {
	logger.Debug("linode.Actual")
	newResource := &Linode{
		Shared: Shared{
			Name:    r.Name,
			CloudID: r.ServerPool.Identifier,
		},
	}

	linodes, _, err := Sdk.Client.Linode.ListInstances(context.TODO(), r.Name, &golinode.ListOptions{})
	if err != nil {
		return nil, nil, err
	}
	ld := len(linodes)
	if ld > 0 {
		newResource.Count = len(linodes)

		// Todo (@kris-nova) once we start to test these implementations we really need to work on the linode logic. Right now we just pick the first one..
		linode := droplets[0]
		id := strconv.Itoa(linode.ID)
		newResource.Name = linode.Name
		newResource.CloudID = id
		newResource.Size = linode.Size.Slug
		newResource.Image = linode.Image.Slug
		newResource.Region = linode.Region.Id
	}
	newResource.BootstrapScripts = r.ServerPool.BootstrapScripts
	newResource.SSHFingerprint = immutable.ProviderConfig().SSH.PublicKeyFingerprint
	newResource.Name = r.ServerPool.Name
	newResource.Count = r.ServerPool.MaxCount
	newResource.Image = r.ServerPool.Image
	newResource.Size = r.ServerPool.Size

	newCluster := r.immutableRender(newResource, immutable)
	return newCluster, newResource, nil
}

func (r *Linode) Expected(immutable *cluster.Cluster) (*cluster.Cluster, cloud.Resource, error) {
	logger.Debug("linode.Expected")
	newResource := &Linode{
		Shared: Shared{
			Name:    r.Name,
			CloudID: r.ServerPool.Identifier,
		},
		Size:             r.ServerPool.Size,
		Region:           immutable.ProviderConfig().Location,
		Image:            r.ServerPool.Image,
		Count:            r.ServerPool.MaxCount,
		SSHFingerprint:   immutable.ProviderConfig().SSH.PublicKeyFingerprint,
		BootstrapScripts: r.ServerPool.BootstrapScripts,
	}

	newCluster := r.immutableRender(newResource, immutable)
	return newCluster, newResource, nil
}

func (r *Linode) Apply(actual, expected cloud.Resource, immutable *cluster.Cluster) (*cluster.Cluster, cloud.Resource, error) {
	logger.Debug("linode.Apply")
	applyResource := expected.(*Linode)
	isEqual, err := compare.IsEqual(actual.(*Linode), expected.(*linode))
	if err != nil {
		return nil, nil, err
	}
	if isEqual {
		return immutable, applyResource, nil
	}

	agent := agent.NewAgent()

	masterIpPrivate := ""
	masterIPPublic := ""
	if r.ServerPool.Type == cluster.ServerPoolTypeNode {
		found := false
		for i := 0; i < MasterIPAttempts; i++ {
			masterTag := ""
			machineConfigs := immutable.MachineProviderConfigs()
			for _, machineConfig := range machineConfigs {
				serverPool := machineConfig.ServerPool
				if serverPool.Type == cluster.ServerPoolTypeMaster {
					masterTag = serverPool.Name
				}
			}
			if masterTag == "" {
				return nil, nil, fmt.Errorf("Unable to find master tag for master IP")
			}
			linodes, _, err := Sdk.Client.Linodes.ListByTag(context.TODO(), masterTag, &golinode.ListOptions{})
			if err != nil {
				logger.Debug("Hanging for master IP.. (%v)", err)
				time.Sleep(time.Duration(MasterIPSleepSecondsPerAttempt) * time.Second)
				continue
			}
			ld := len(linodes)
			if ld == 0 {
				logger.Debug("Hanging for master IP..")
				time.Sleep(time.Duration(MasterIPSleepSecondsPerAttempt) * time.Second)
				continue
			}
			if ld > 1 {
				return nil, nil, fmt.Errorf("Found [%d] linodes for tag [%s]", ld, masterTag)
			}
			linode := droplets[0]

			masterIPPublic, err = linode.PublicIPv4()
			if err != nil || masterIPPublic == "" {
				logger.Debug("Hanging for master IP..")
				time.Sleep(time.Duration(MasterIPSleepSecondsPerAttempt) * time.Second)
				continue
			}

			if !immutable.ProviderConfig().Components.ComponentVPN {
				logger.Info("Waiting for Private IP address...")
				masterIpPrivate, err = linode.PrivateIPv4()
				if err != nil || masterIpPrivate == "" {
					return nil, nil, fmt.Errorf("Unable to detect private IP: %v", err)
				}
				found = true
			} else {
				logger.Info("Setting up VPN on Linodes... this could take a little bit longer...")
				pubPath := local.Expand(immutable.ProviderConfig().SSH.PublicKeyPath)
				privPath := strings.Replace(pubPath, ".pub", "", 1)
				scp := scp.NewSecureCopier(immutable.ProviderConfig().SSH.User, masterIPPublic, "22", privPath, agent)
				masterVpnIP, err := scp.ReadBytes("/tmp/.ip")
				if err != nil {
					logger.Debug("Hanging for VPN IP.. /tmp/.ip (%v)", err)
					time.Sleep(time.Duration(MasterIPSleepSecondsPerAttempt) * time.Second)
					continue
				}
				masterIpPrivate = strings.Replace(string(masterVpnIP), "\n", "", -1)
				openvpnConfig, err := scp.ReadBytes("/tmp/clients.conf")
				if err != nil {
					logger.Debug("Hanging for VPN config.. /tmp/clients.ovpn (%v)", err)
					time.Sleep(time.Duration(MasterIPSleepSecondsPerAttempt) * time.Second)
					continue
				}

				openvpnConfigEscaped := strings.Replace(string(openvpnConfig), "\n", "\\n", -1)
				immutable.ProviderConfig().Values.ItemMap["INJECTEDCONF"] = openvpnConfigEscaped

				found = true
			}

			// Todo (@kris-nova) this is obviously not immutable
			immutable.ProviderConfig().Values.ItemMap["INJECTEDMASTER"] = fmt.Sprintf("%s:%s", masterIpPrivate, immutable.ProviderConfig().KubernetesAPI.Port)

			break
		}
		if !found {
			return nil, nil, fmt.Errorf("Unable to find Master IP after defined wait")
		}
	}

	immutable.ProviderConfig().Values.ItemMap["INJECTEDPORT"] = immutable.ProviderConfig().KubernetesAPI.Port

	userData, err := script.BuildBootstrapScript(r.ServerPool.BootstrapScripts, immutable)
	if err != nil {
		return nil, nil, err
	}

	sshID, err := strconv.Atoi(immutable.ProviderConfig().SSH.Identifier)
	if err != nil {
		return nil, nil, err
	}

	var linode *golinode.Linode
	for j := 0; j < expected.(*Linode).Count; j++ {
		createRequest := &golinode.LinodeCreateRequest{
			Name:   fmt.Sprintf("%s-%d", expected.(*Linode).Name, j),
			Region: expected.(*Linode).Region,
			Size:   expected.(*Linode).Size,
			Image: golinode.LinodeCreateImage{
				Slug: expected.(*Linode).Image,
			},
			Tags:              []string{expected.(*Linode).Name},
			PrivateNetworking: true,
			SSHKeys: []golinode.LinodeCreateSSHKey{
				{
					ID:          sshID,
					Fingerprint: expected.(*Linode).SSHFingerprint,
				},
			},
			UserData: string(userData),
		}
		linode, _, err = Sdk.Client.Linodes.Create(context.TODO(), createRequest)
		if err != nil {
			return nil, nil, err
		}
		logger.Success("Created Linode [%d]", linode.ID)
	}

	newResource := &Linode{
		Shared: Shared{
			Name:    r.ServerPool.Name,
			CloudID: strconv.Itoa(linode.ID),
		},
		Image:            linode.Image.Slug,
		Size:             linode.Size.Slug,
		Region:           linode.Region.Slug,
		Count:            expected.(*Linode).Count,
		BootstrapScripts: expected.(*Linode).BootstrapScripts,
	}

	// todo (@kris-nova) this is obviously not immutable
	immutable.ProviderConfig().KubernetesAPI.Endpoint = masterIPPublic

	newCluster := r.immutableRender(newResource, immutable)
	return newCluster, newResource, nil
}
func (r *Linode) Delete(actual cloud.Resource, immutable *cluster.Cluster) (*cluster.Cluster, cloud.Resource, error) {
	logger.Debug("linode.Delete")
	deleteResource := actual.(*Linode)
	if deleteResource.Name == "" {
		return nil, nil, fmt.Errorf("Unable to delete linode resource without Name [%s]", deleteResource.Name)
	}

	linodes, _, err := Sdk.Client.Linodes.ListByTag(context.TODO(), r.Name, &golinode.ListOptions{})
	if err != nil {
		return nil, nil, err
	}
	if len(linodes) != actual.(*Linode).Count {
		for i := 0; i < DeleteAttempts; i++ {
			logger.Info("Linode count mis-match, trying query again")
			time.Sleep(5 * time.Second)
			linodes, _, err = Sdk.Client.Linodes.ListByTag(context.TODO(), r.Name, &golinode.ListOptions{})
			if err != nil {
				return nil, nil, err
			}
			if len(linodes) == actual.(*Linode).Count {
				break
			}
		}
	}

	for _, linode := range droplets {
		for i := 0; i < DeleteAttempts; i++ {
			if linode.Status == "new" {
				logger.Debug("Waiting for Linode creation to finish [%d]...", linode.ID)
				time.Sleep(DeleteSleepSecondsPerAttempt * time.Second)
			} else {
				break
			}
		}
		_, err = Sdk.Client.Linodes.Delete(context.TODO(), linode.ID)
		if err != nil {
			return nil, nil, err
		}
		logger.Success("Deleted Linode [%d]", linode.ID)
	}

	// Kubernetes API
	// todo (@kris-nova) this is obviously not immutable
	immutable.ProviderConfig().KubernetesAPI.Endpoint = ""

	newResource := &Linode{}
	newResource.Name = actual.(*Linode).Name
	newResource.Tags = actual.(*Linode).Tags
	newResource.Image = actual.(*Linode).Image
	newResource.Size = actual.(*Linode).Size
	newResource.Count = actual.(*Linode).Count
	newResource.Region = actual.(*Linode).Region
	newResource.BootstrapScripts = actual.(*Linode).BootstrapScripts

	newCluster := r.immutableRender(newResource, immutable)
	return newCluster, newResource, nil
}

func (r *Linode) immutableRender(newResource cloud.Resource, inaccurateCluster *cluster.Cluster) *cluster.Cluster {
	logger.Debug("linode.Render")
	newCluster := inaccurateCluster
	serverPool := &cluster.ServerPool{}
	serverPool.Type = r.ServerPool.Type
	serverPool.Image = newResource.(*Linode).Image
	serverPool.Size = newResource.(*Linode).Size
	serverPool.Name = newResource.(*Linode).Name
	serverPool.MaxCount = newResource.(*Linode).Count
	serverPool.BootstrapScripts = newResource.(*Linode).BootstrapScripts
	found := false

	machineProviderConfigs := newCluster.MachineProviderConfigs()
	for i := 0; i < len(machineProviderConfigs); i++ {
		machineProviderConfig := machineProviderConfigs[i]

		if machineProviderConfig.ServerPool.Name == newResource.(*Linode).Name {
			machineProviderConfig.ServerPool.Image = newResource.(*Linode).Image
			machineProviderConfig.ServerPool.Size = newResource.(*Linode).Size
			machineProviderConfig.ServerPool.MaxCount = newResource.(*Linode).Count
			machineProviderConfig.ServerPool.BootstrapScripts = newResource.(*Linode).BootstrapScripts
			found = true
			machineProviderConfigs[i] = machineProviderConfig
			newCluster.SetMachineProviderConfigs(machineProviderConfigs)
		}
	}
	if !found {
		providerConfig := []*cluster.MachineProviderConfig{
			{
				ServerPool: serverPool,
			},
		}
		newCluster.NewMachineSetsFromProviderConfigs(providerConfig)
	}
	providerConfig := newCluster.ProviderConfig()
	providerConfig.Location = newResource.(*Linode).Region
	newCluster.SetProviderConfig(providerConfig)
	return newCluster
}
