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

package bpfdclient

import (
	"context"
	"fmt"
	"os"

	"github.com/cilium/ebpf"
	bpfdiov1alpha1 "github.com/redhat-et/bpfd/bpfd-operator/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
)

const (
	DefaultMapDir = "/run/bpfd/fs/maps"
)

// GetMaps is meant to be used by applications wishing to use BPFD. It takes in a bpf program
// name and a list of map names.  If bpfd is up and running this function will succeed, if
// not it will return an error and the user can decide wether or not to use bpfd as the loader
// for their bpfProgram
func GetMaps(bpfProgramConfigName string, mapNames []string, opts *ebpf.LoadPinOptions) (map[string]*ebpf.Map, error) {
	bpfMaps := map[string]*ebpf.Map{}

	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("error getting in-cluster kube-config: %v", err)
	}

	ctx := context.Background()

	// Get the nodename where this pod is running
	nodeName := os.Getenv("NODENAME")
	if nodeName == "" {
		return nil, fmt.Errorf("NODENAME env var not set")
	}
	bpfProgramName := bpfProgramConfigName + "-" + nodeName

	// Get map pin path from relevant BpfProgram Object with a dynamic go-client
	clientSet := dynamic.NewForConfigOrDie(config)

	bpfProgramResource := schema.GroupVersionResource{
		Group:    "bpfd.io",
		Version:  "v1alpha1",
		Resource: "bpfprograms",
	}

	bpfProgramBlob, err := clientSet.Resource(bpfProgramResource).
		Get(ctx, bpfProgramName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("error getting BpfProgram %s: %v", bpfProgramName, err)
	}

	var bpfProgram bpfdiov1alpha1.BpfProgram
	err = runtime.DefaultUnstructuredConverter.FromUnstructured(bpfProgramBlob.UnstructuredContent(), &bpfProgram)
	if err != nil {
		panic(err)
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
