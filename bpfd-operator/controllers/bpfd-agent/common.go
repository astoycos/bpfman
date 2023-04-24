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

package bpfdagent

import (
	"context"
	"fmt"
	"reflect"
	"time"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	"github.com/go-logr/logr"
	bpfdiov1alpha1 "github.com/redhat-et/bpfd/bpfd-operator/apis/v1alpha1"
	bpfdagentinternal "github.com/redhat-et/bpfd/bpfd-operator/controllers/bpfd-agent/internal"
	gobpfd "github.com/redhat-et/bpfd/clients/gobpfd/v1"
	"google.golang.org/grpc"
	v1 "k8s.io/api/core/v1"
)

//+kubebuilder:rbac:groups=bpfd.io,resources=bpfprograms,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=bpfd.io,resources=bpfprograms/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=bpfd.io,resources=bpfprograms/finalizers,verbs=update
//+kubebuilder:rbac:groups=core,resources=nodes,verbs=get;list;watch
//+kubebuilder:rbac:groups=core,resources=secrets,namespace=bpfd,verbs=get

// ReconcilerCommon provides a skeleton for a all Program Reconcilers.
type ReconcilerCommon struct {
	client.Client
	Scheme           *runtime.Scheme
	GrpcConn         *grpc.ClientConn
	BpfdClient       gobpfd.LoaderClient
	Logger           logr.Logger
	NodeName         string
	Namespace        string
	bpfProgram       *bpfdiov1alpha1.BpfProgram
	expectedPrograms map[string]map[string]string
}

// bpfdReconciler defines a k8s reconciler which can program bpfd.
type bpfdReconciler interface {
	getRecCommon() *ReconcilerCommon
	reconcileBpfdPrograms(context.Context,
		map[string]*gobpfd.ListResponse_ListResult,
		interface{},
		bool) (bool, error)
}

type bpfProgramConditionType string

const (
	XdpProgramControllerFinalizer                                = "bpfd.io.xdpProgramController/finalizer"
	TcProgramControllerFinalizer                                 = "bpfd.io.tcProgramController/finalizer"
	TracepointProgramControllerFinalizer                         = "bpfd.io.tracepointProgramController/finalizer"
	retryDurationAgent                                           = 5 * time.Second
	BpfProgCondLoaded                    bpfProgramConditionType = "Loaded"
	BpfProgCondNotLoaded                 bpfProgramConditionType = "NotLoaded"
	BpfProgCondNotUnloaded               bpfProgramConditionType = "NotUnLoaded"
	BpfProgCondNotSelected               bpfProgramConditionType = "NotSelected"
)

func (b bpfProgramConditionType) Condition() metav1.Condition {
	cond := metav1.Condition{}

	switch b {
	case BpfProgCondLoaded:
		cond = metav1.Condition{
			Type:    string(BpfProgCondLoaded),
			Status:  metav1.ConditionTrue,
			Reason:  "bpfdLoaded",
			Message: "Successfully loaded bpfProgram",
		}
	case BpfProgCondNotLoaded:
		cond = metav1.Condition{
			Type:    string(BpfProgCondNotLoaded),
			Status:  metav1.ConditionTrue,
			Reason:  "bpfdNotLoaded",
			Message: "Failed to load bpfProgram",
		}
	case BpfProgCondNotUnloaded:
		cond = metav1.Condition{
			Type:    string(BpfProgCondNotUnloaded),
			Status:  metav1.ConditionTrue,
			Reason:  "bpfdNotUnloaded",
			Message: "Failed to unload bpfProgram",
		}
	case BpfProgCondNotSelected:
		cond = metav1.Condition{
			Type:    string(BpfProgCondNotSelected),
			Status:  metav1.ConditionTrue,
			Reason:  "nodeNotSelected",
			Message: "This node is not selected to run the bpfProgram",
		}
	}

	return cond
}

// Only return node updates for our node (all events)
func nodePredicate(nodeName string) predicate.Funcs {
	return predicate.Funcs{
		GenericFunc: func(e event.GenericEvent) bool {
			return e.Object.GetLabels()["kubernetes.io/hostname"] == nodeName
		},
		CreateFunc: func(e event.CreateEvent) bool {
			return e.Object.GetLabels()["kubernetes.io/hostname"] == nodeName
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			return e.ObjectNew.GetLabels()["kubernetes.io/hostname"] == nodeName
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			return e.Object.GetLabels()["kubernetes.io/hostname"] == nodeName
		},
	}
}

func isNodeSelected(selector *metav1.LabelSelector, nodeLabels map[string]string) (bool, error) {
	// Logic to check if this node is selected by the BpfProgramConfig object
	selectorTool, err := metav1.LabelSelectorAsSelector(selector)
	if err != nil {
		return false, fmt.Errorf("failed to parse nodeSelector: %v",
			err)
	}

	nodeLabelSet, err := labels.ConvertSelectorToLabelsMap(labels.FormatLabels(nodeLabels))
	if err != nil {
		return false, fmt.Errorf("failed to parse node labels : %v",
			err)
	}

	return selectorTool.Matches(nodeLabelSet), nil
}

func getInterfaces(interfaceSelector *bpfdiov1alpha1.InterfaceSelector, ourNode *v1.Node) ([]string, error) {
	var interfaces []string

	if interfaceSelector.Interface != nil {
		interfaces = append(interfaces, *interfaceSelector.Interface)
		return interfaces, nil
	}

	if interfaceSelector.PrimaryNodeInterface != nil {
		nodeIface, err := bpfdagentinternal.GetPrimaryNodeInterface(ourNode)
		if err != nil {
			return nil, err
		}

		interfaces = append(interfaces, nodeIface)
	}

	return interfaces, fmt.Errorf("no interfaces selected")

}

// Move to bpfd core helpers
func (r *ReconcilerCommon) listBpfdPrograms(ctx context.Context, programType bpfdagentinternal.SupportedProgramType) (map[string]*gobpfd.ListResponse_ListResult, error) {
	listReq := gobpfd.ListRequest{
		ProgramType: programType.Int32(),
	}

	out := map[string]*gobpfd.ListResponse_ListResult{}

	listResponse, err := r.BpfdClient.List(ctx, &listReq)
	if err != nil {
		return nil, err
	}

	for _, result := range listResponse.Results {
		out[result.Id] = result
	}

	return out, nil
}

func (r *ReconcilerCommon) removeFinalizer(ctx context.Context, o client.Object, finalizer string) (bool, error) {
	r.Logger.V(1).Info("bpfProgram %s is deleted, don't load program, remove finalizer", o.GetName())

	if changed := controllerutil.RemoveFinalizer(o, finalizer); changed {
		err := r.Update(ctx, o)
		if err != nil {
			r.Logger.Error(err, "failed to set remove bpfProgram Finalizer")
			return true, nil
		}
	}

	return false, nil
}

func (r *ReconcilerCommon) updateStatus(ctx context.Context, prog *bpfdiov1alpha1.BpfProgram, cond bpfProgramConditionType) (bool, error) {
	meta.SetStatusCondition(&prog.Status.Conditions, cond.Condition())

	if err := r.Status().Update(ctx, prog); err != nil {
		r.Logger.Error(err, "failed to set bpfProgram object status")
		return true, nil
	}

	return false, nil
}

func reconcileProgram(ctx context.Context,
	rec bpfdReconciler,
	program client.Object,
	common *bpfdiov1alpha1.BpfProgramCommon,
	ourNode *v1.Node,
	programMap map[string]*gobpfd.ListResponse_ListResult) (bool, error) {
	r := rec.getRecCommon()
	bpfProgram := &bpfdiov1alpha1.BpfProgram{}
	bpfProgramName := fmt.Sprintf("%s-%s", program.GetName(), r.NodeName)

	// Always create the bpfProgram Object if it doesn't exist
	err := r.Get(ctx, types.NamespacedName{Namespace: v1.NamespaceAll, Name: bpfProgramName}, r.bpfProgram)
	if err != nil {
		if errors.IsNotFound(err) {
			r.Logger.Info("bpfProgram object doesn't exist creating...")
			bpfProgram = &bpfdiov1alpha1.BpfProgram{
				ObjectMeta: metav1.ObjectMeta{
					Name:       bpfProgramName,
					Finalizers: []string{TcProgramControllerFinalizer},
					Labels:     map[string]string{"owningConfig": program.GetName()},
				},
				Spec: bpfdiov1alpha1.BpfProgramSpec{
					Node:     r.NodeName,
					Type:     bpfdagentinternal.Tc.String(),
					Programs: make(map[string]map[string]string),
				},
				Status: bpfdiov1alpha1.BpfProgramStatus{Conditions: []metav1.Condition{}},
			}

			// Make the corresponding BpfProgramConfig the owner
			if err = ctrl.SetControllerReference(program, bpfProgram, r.Scheme); err != nil {
				return false, fmt.Errorf("failed to bpfProgram object owner reference: %v", err)
			}

			opts := client.CreateOptions{}
			if err = r.Create(ctx, bpfProgram, &opts); err != nil {
				return false, fmt.Errorf("failed to create bpfProgram object: %v",
					err)
			}

			r.bpfProgram = bpfProgram

			return false, nil
		} else {
			return false, fmt.Errorf("failed getting bpfProgram %s : %v",
				bpfProgramName, err)
		}
	}

	isNodeSelected, err := isNodeSelected(&common.NodeSelector, ourNode.Labels)
	if err != nil {
		return false, fmt.Errorf("failed to check if node is selected: %v", err)
	}

	bytecode, err := bpfdagentinternal.GetBytecode(r.Client, r.Namespace, &common.ByteCode)
	if err != nil {
		return false, fmt.Errorf("failed to process bytecode selector: %v", err)
	}

	rec.reconcileBpfdPrograms(ctx, programMap, bytecode, isNodeSelected)

	r.Logger.V(1).Info("Updating bpfProfgram Object", "Programs", r.expectedPrograms)

	if !reflect.DeepEqual(bpfProgram.Spec.Programs, r.expectedPrograms) {
		if err := r.Update(ctx, bpfProgram, &client.UpdateOptions{}); err != nil {
			r.Logger.Error(err, "failed to update bpfProgram's Programs")
			return true, nil
		}
	}

	// Finally update status upon success
	return r.updateStatus(ctx, bpfProgram, BpfProgCondLoaded)
}
