/*
Copyright 2022.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package helpers

import (
	"context"
	"fmt"
	"os"

	"github.com/cilium/ebpf"
	bpfdiov1alpha1 "github.com/redhat-et/bpfd/bpfd-operator/apis/v1alpha1"
	bpfdclientset "github.com/redhat-et/bpfd/bpfd-operator/pkg/client/clientset/versioned"
	"k8s.io/apimachinery/pkg/api/errors"

	"k8s.io/client-go/tools/clientcmd"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
)

const (
	DefaultMapDir = "/run/bpfd/fs/maps"
)

type ProgType string

const (
	Tc         ProgType = "TC"
	Xdp        ProgType = "XDP"
	TracePoint          = "TRACEPOINT"
)

// Get bpfd Kubernetes Client dynamically switches between in cluster and out of 
// cluster config setup.
func GetClientOrDie() *bpfdclientset.Clientset {
	config, err := rest.InClusterConfig()
	if err != nil {
		kubeConfig :=
			clientcmd.NewDefaultClientConfigLoadingRules().GetDefaultFilename()
		config, err = clientcmd.BuildConfigFromFlags("", kubeConfig)
		if err != nil {
			panic(err)
		}

		fmt.Println("Program running from outside of the cluster, picking config from --kubeconfig flag")
	} else {
		fmt.Println("Program running inside the cluster, picking the in-cluster configuration")
	}

	return bpfdclientset.NewForConfigOrDie(config)
}

// GetMaps is meant to be used by applications wishing to use BPFD. It takes in a bpf program
// name and a list of map names.  If bpfd is up and running this function will succeed, if
// not it will return an error and the user can decide wether or not to use bpfd as the loader
// for their bpfProgram
func GetMaps(c *bpfdclientset.Clientset, bpfProgramConfigName string, mapNames []string, opts *ebpf.LoadPinOptions) (map[string]*ebpf.Map, error) {
	bpfMaps := map[string]*ebpf.Map{}
	ctx := context.Background()

	// Get the nodename where this pod is running
	nodeName := os.Getenv("NODENAME")
	if nodeName == "" {
		return nil, fmt.Errorf("NODENAME env var not set")
	}
	bpfProgramName := bpfProgramConfigName + "-" + nodeName

	bpfProgram, err := c.BpfdV1alpha1().BpfPrograms().Get(ctx, bpfProgramName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("error getting BpfProgram %s: %v", bpfProgramName, err)
	}

	// TODO (astoycos) This doesn't support multiple programs in a single bpfProgram Object yet
	for _, v := range bpfProgram.Spec.Programs {
		for _, mapName := range mapNames {

			if pinPath, ok := v.Maps[mapName]; !ok {
				return nil, fmt.Errorf("map: %s not found", mapName)
			} else {
				bpfMaps[mapName], err = ebpf.LoadPinnedMap(pinPath, opts)
				if err != nil {
					return nil, err
				}
			}

		}
	}

	return bpfMaps, nil
}

func NewBpfProgramConfig(name string, progType ProgType) *bpfdiov1alpha1.BpfProgramConfig {
	switch progType {
	case Xdp, Tc:
		return &bpfdiov1alpha1.BpfProgramConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name: name,
			},
			Spec: bpfdiov1alpha1.BpfProgramConfigSpec{
				Type: string(progType),
				AttachPoint: bpfdiov1alpha1.BpfProgramAttachPoint{
					NetworkMultiAttach: &bpfdiov1alpha1.BpfNetworkMultiAttach{},
				},
			},
		}
	case TracePoint:
		return &bpfdiov1alpha1.BpfProgramConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name: name,
			},
			Spec: bpfdiov1alpha1.BpfProgramConfigSpec{
				Type: string(progType),
				AttachPoint: bpfdiov1alpha1.BpfProgramAttachPoint{
					SingleAttach: &bpfdiov1alpha1.BpfSingleAttach{},
				},
			},
		}
	default:
		return nil
	}
}

func CreateOrUpdateBpfProgConf(c *bpfdclientset.Clientset, progConfig *bpfdiov1alpha1.BpfProgramConfig) error {
	progName := progConfig.GetName()
	ctx := context.Background()

	_, err := c.BpfdV1alpha1().BpfProgramConfigs().Get(ctx, progName, metav1.GetOptions{})
	if err != nil {
		// Create if not found
		if errors.IsNotFound(err) {
			_, err = c.BpfdV1alpha1().BpfProgramConfigs().Create(ctx, progConfig, metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("error creating BpfProgramConfig %s: %v", progName, err)
			}

			return nil
		}
		return fmt.Errorf("error getting BpfProgramConfig %s: %v", progName, err)
	}

	// Update if already exists
	_, err = c.BpfdV1alpha1().BpfProgramConfigs().Update(ctx, progConfig, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("error updating BpfProgramConfig %s: %v", progName, err)
	}

	return nil
}

func WaitForBpfProgConfLoad(progName string, ) error 
