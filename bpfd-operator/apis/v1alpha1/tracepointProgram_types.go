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

// All fields are required unless explicitly marked optional
// +kubebuilder:validation:Required
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +genclient:nonNamespaced
//+kubebuilder:object:root=true
//+kubebuilder:subresource:status
//+kubebuilder:resource:scope=Cluster

// BpfProgramConfig is the Schema for the Bpfprogramconfigs API
type TracepointProgram struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec TracepointProgramSpec `json:"spec"`
	// +optional
	Status TracepointProgramStatus `json:"status,omitempty"`
}

// +kubebuilder:validation:Enum=aborted;drop;pass;tx;redirect;dispatcher_return
type TracepointProceedOnValue string

// BpfProgramConfigSpec defines the desired state of BpfProgramConfig
type TracepointProgramSpec struct {
	BpfProgramCommon `json:",inline"`

	// Name refers to the name of the tracepoint to attach to
	Name string `json:"name"`
}

// TracepointProgramStatus defines the observed state of TracepointProgram
type TracepointProgramStatus struct {
	// Conditions houses the global cluster state for the BpfProgram
	// Known .status.conditions.type are: "Available", "Progressing", and "Degraded"
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type" protobuf:"bytes,1,rep,name=conditions"`
}

// +kubebuilder:object:root=true
// TracepointProgramList contains a list of TracepointPrograms
type TracepointProgramList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []TracepointProgram `json:"items"`
}
