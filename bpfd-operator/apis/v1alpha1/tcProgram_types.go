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
type TcProgram struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec TcProgramSpec `json:"spec"`
	// +optional
	Status TcProgramStatus `json:"status,omitempty"`
}

// +kubebuilder:validation:Enum=unspec;ok;reclassify;shot;pipe;stolen;queued;repeat;redirect;trap;dispatcher_return
type TcProceedOnValue string

// BpfProgramConfigSpec defines the desired state of BpfProgramConfig
type TcProgramSpec struct {
	BpfProgramCommon `json:",inline"`
	
	// Selector to determine the network interface (or interfaces)
	InterfaceSelector InterfaceSelector `json:"interfaceselector"`

	// Priority specifies the priority of the bpf program in relation to
	// other programs of the same type with the same attach point. It is a value
	// from 0 to 1000 where lower values have higher precedence.
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=1000
	Priority int32 `json:"priority"`

	// Direction specifies the direction of traffic the bpfprogram should
	// attach to for a given network device, this field should only be
	// set for programs of type TC.
	// +kubebuilder:validation:Enum=NONE;INGRESS;EGRESS
	// +kubebuilder:default=NONE
	// +optional
	Direction string `json:"direction"`

	// ProceedOn allows the user to call other programs in chain on this exit code.
	// Multiple values are supported by repeating the parameter. This feature
	// is only applicable for XDP programs.
	// NOTE: These values are not updatable following bpfProgramConfig creation.
	// +optional
	ProceedOn []TcProceedOnValue `json:"proceedon"`
}

// TcProgramStatus defines the observed state of TcProgram
type TcProgramStatus struct {
	// Conditions houses the global cluster state for the BpfProgram
	// Known .status.conditions.type are: "Available", "Progressing", and "Degraded"
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type" protobuf:"bytes,1,rep,name=conditions"`
}

//+kubebuilder:object:root=true
// TcProgramList contains a list of TcPrograms
type TcProgramList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []TcProgram `json:"items"`
}