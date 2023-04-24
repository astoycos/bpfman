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

	"k8s.io/apimachinery/pkg/types"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/source"

	bpfdiov1alpha1 "github.com/redhat-et/bpfd/bpfd-operator/apis/v1alpha1"
	bpfdagentinternal "github.com/redhat-et/bpfd/bpfd-operator/controllers/bpfd-agent/internal"

	gobpfd "github.com/redhat-et/bpfd/clients/gobpfd/v1"
	v1 "k8s.io/api/core/v1"
)

//+kubebuilder:rbac:groups=bpfd.io,resources=tracepointprograms,verbs=get;list;watch

// BpfProgramReconciler reconciles a BpfProgram object
type TracePointProgramReconciler struct {
	ReconcilerCommon
	currentTracepointProgram *bpfdiov1alpha1.TracepointProgram
	ourNode                  *v1.Node
}

func (r *TracePointProgramReconciler) getRecCommon() *ReconcilerCommon {
	return &r.ReconcilerCommon
}

// SetupWithManager sets up the controller with the Manager.
// The Bpfd-Agent should reconcile whenever a BpfProgramConfig is updated,
// load the program to the node via bpfd, and then create a bpfProgram object
// to reflect per node state information.
func (r *TracePointProgramReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&bpfdiov1alpha1.TracepointProgram{}, builder.WithPredicates(predicate.And(predicate.GenerationChangedPredicate{}, predicate.ResourceVersionChangedPredicate{}))).
		Owns(&bpfdiov1alpha1.BpfProgram{}, builder.WithPredicates(predicate.And(predicate.GenerationChangedPredicate{}, predicate.ResourceVersionChangedPredicate{}))).
		// Only trigger reconciliation if node labels change since that could
		// make the BpfProgramConfig no longer select the Node. Additionally only
		// care about node events specific to our node
		Watches(
			&source.Kind{Type: &v1.Node{}},
			&handler.EnqueueRequestForObject{},
			builder.WithPredicates(predicate.And(predicate.LabelChangedPredicate{}, nodePredicate(r.NodeName))),
		).
		Complete(r)
}

func (r *TracePointProgramReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	r.Logger = log.FromContext(ctx)

	// Lookup K8s node object for this bpfd-agent This should always succeed
	if err := r.Get(ctx, types.NamespacedName{Namespace: v1.NamespaceAll, Name: r.NodeName}, r.ourNode); err != nil {
		return ctrl.Result{Requeue: false}, fmt.Errorf("failed getting bpfd-agent node %s : %v",
			req.NamespacedName, err)
	}

	TracepointPrograms := &bpfdiov1alpha1.TracepointProgramList{}

	opts := []client.ListOption{}

	if err := r.List(ctx, TracepointPrograms, opts...); err != nil {
		return ctrl.Result{Requeue: false}, fmt.Errorf("failed getting TcPrograms for full reconcile %s : %v",
			req.NamespacedName, err)
	}

	if len(TracepointPrograms.Items) == 0 {
		return ctrl.Result{Requeue: false}, nil
	}

	// Get existing ebpf state from bpfd.
	programMap, err := r.listBpfdPrograms(ctx, bpfdagentinternal.Tc)
	if err != nil {
		r.Logger.Error(err, "failed to list loaded bpfd programs")
		return ctrl.Result{Requeue: true, RequeueAfter: retryDurationAgent}, nil
	}

	// Reconcile every TcProgram Object
	// note: This doesn't necessarily result in any extra grpc calls to bpfd
	for _, tcProgram := range TracepointPrograms.Items {
		r.Logger.Info("bpfd-agent is reconciling", "bpfProgramConfig", tcProgram.Name)
		r.currentTracepointProgram = &tcProgram
		retry, err := reconcileProgram(ctx, r, r.currentTracepointProgram, &r.currentTracepointProgram.Spec.BpfProgramCommon, r.ourNode, programMap)
		if err != nil {
			r.Logger.Error(err, "Reconciling BpfProgramConfig Failed", "BpfProgramConfigName", r.currentTracepointProgram.Name, "Retrying", retry)
			return ctrl.Result{Requeue: retry, RequeueAfter: retryDurationAgent}, nil
		}
	}

	return ctrl.Result{Requeue: false}, nil
}

// TODO(astoycos) convert this to not operate on the bpfProgramObject
func (r *TracePointProgramReconciler) reconcileBpfdPrograms(ctx context.Context,
	existingBpfPrograms map[string]*gobpfd.ListResponse_ListResult,
	bytecode interface{},
	isNodeSelected bool) (bool, error) {

	tracepointProgram := r.currentTracepointProgram

	bpfProgramEntries := r.bpfProgram.Spec.Programs

	loadRequest := &gobpfd.LoadRequest{}

	Id := tracepointProgram.Name
	loadRequest.Common = bpfdagentinternal.BuildBpfdCommon(bytecode, tracepointProgram.Spec.SectionName, bpfdagentinternal.Tracepoint, Id, tracepointProgram.Spec.GlobalData)

	loadRequest.AttachInfo = &gobpfd.LoadRequest_TracepointAttachInfo{
		TracepointAttachInfo: &gobpfd.TracepointAttachInfo{
			Tracepoint: tracepointProgram.Spec.Name,
		},
	}

	existingProgram, doesProgramExist := existingBpfPrograms[Id]
	if !doesProgramExist {
		r.Logger.V(1).Info("TcProgram doesn't exist on node")

		// If BpfProgramConfig is being deleted just remove finalizer so the
		// owner relationship can take care of cleanup
		if !tracepointProgram.DeletionTimestamp.IsZero() {
			return r.removeFinalizer(ctx, tracepointProgram, TcProgramControllerFinalizer)
		}

		// Make sure if we're not selected just exit
		if !isNodeSelected {
			r.Logger.V(1).Info("bpfProgramConfig does not select this node")
			// Write NodeNodeSelected status
			return r.updateStatus(ctx, r.bpfProgram, BpfProgCondNotSelected)

		}

		// otherwise load it
		bpfProgramEntry, err := bpfdagentinternal.LoadBpfdProgram(ctx, r.BpfdClient, loadRequest)
		if err != nil {
			r.Logger.Error(err, "Failed to load TcProgram")
			return r.updateStatus(ctx, r.bpfProgram, BpfProgCondNotLoaded)
		}

		bpfProgramEntries[Id] = bpfProgramEntry
	}

	// BpfProgram exists but either BpfProgramConfig is being deleted or node is no
	// longer selected....unload program
	if !tracepointProgram.DeletionTimestamp.IsZero() || !isNodeSelected {
		r.Logger.V(1).Info("bpfProgram exists on Node but is scheduled for deletion or node is no longer selected", "isDeleted", !tracepointProgram.DeletionTimestamp.IsZero(),
			"isSelected", isNodeSelected)
		if controllerutil.ContainsFinalizer(r.bpfProgram, TcProgramControllerFinalizer) {
			if err := bpfdagentinternal.UnloadBpfdProgram(ctx, r.BpfdClient, Id); err != nil {
				r.Logger.Error(err, "Failed to unload TcProgram")
				return r.updateStatus(ctx, r.bpfProgram, BpfProgCondNotLoaded)
			}

			r.removeFinalizer(ctx, tracepointProgram, TcProgramControllerFinalizer)

			// If K8s hasn't cleaned up here it means we're no longer selected
			// write NodeNodeSelected status ignoring error (object may not exist)
			return r.updateStatus(ctx, r.bpfProgram, BpfProgCondNotSelected)
		}

		return false, nil
	}

	// BpfProgram exists but is not correct state, unload and recreate
	if !bpfdagentinternal.DoesProgExist(existingProgram, loadRequest) {
		if err := bpfdagentinternal.UnloadBpfdProgram(ctx, r.BpfdClient, Id); err != nil {
			r.Logger.Error(err, "Failed to unload TcProgram")
			return r.updateStatus(ctx, r.bpfProgram, BpfProgCondNotLoaded)
		}

		bpfProgramEntry, err := bpfdagentinternal.LoadBpfdProgram(ctx, r.BpfdClient, loadRequest)
		if err != nil {
			r.Logger.Error(err, "Failed to load TcProgram")
			return r.updateStatus(ctx, r.bpfProgram, BpfProgCondNotLoaded)
		}

		bpfProgramEntries[Id] = bpfProgramEntry
	} else {
		// Program already exists, but bpfProgram K8s Object might not be up to date
		if _, ok := r.bpfProgram.Spec.Programs[Id]; !ok {
			maps, err := bpfdagentinternal.GetMapsForUUID(Id)
			if err != nil {
				r.Logger.Error(err, "failed to get bpfProgram's Maps")
				return r.updateStatus(ctx, r.bpfProgram, BpfProgCondNotLoaded)
			}

			bpfProgramEntries[Id] = maps
		} else {
			// Program exists and bpfProgram K8s Object is up to date
			r.Logger.V(1).Info("Ignoring Object Change nothing to do in bpfd")
		}
	}

	r.expectedPrograms = bpfProgramEntries

	return false, nil
}
