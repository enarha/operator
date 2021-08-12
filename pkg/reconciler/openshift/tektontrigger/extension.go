/*
Copyright 2020 The Tekton Authors

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

package tektontrigger

import (
	"context"
	mf "github.com/manifestival/manifestival"
	"github.com/tektoncd/operator/pkg/apis/operator/v1alpha1"
	"github.com/tektoncd/operator/pkg/client/clientset/versioned"
	operatorclient "github.com/tektoncd/operator/pkg/client/injection/client"
	"github.com/tektoncd/operator/pkg/reconciler/common"
	occommon "github.com/tektoncd/operator/pkg/reconciler/openshift/common"
	"k8s.io/apimachinery/pkg/apis/meta/v1"
)

const triggersPrefix = "quay.io/openshift-pipeline/tektoncd-triggers-"

func OpenShiftExtension(ctx context.Context) common.Extension {
	ext := openshiftExtension{
		operatorClientSet: operatorclient.Get(ctx),
	}
	return ext
}

type openshiftExtension struct {
	operatorClientSet versioned.Interface
}

func (oe openshiftExtension) Transformers(comp v1alpha1.TektonComponent) []mf.Transformer {
	return []mf.Transformer{
		occommon.UpdateDeployments(triggersPrefix, map[string]string{}),
		occommon.RemoveRunAsGroup(),
		occommon.ApplyCABundles,
	}
}
func (oe openshiftExtension) PreReconcile(ctx context.Context, tc v1alpha1.TektonComponent) error {
	tt := tc.(*v1alpha1.TektonTrigger)
	if crUpdated := SetDefault(&tt.Spec.TriggersProperties); crUpdated {
		if _, err := oe.operatorClientSet.OperatorV1alpha1().TektonTriggers().Update(ctx, tt, v1.UpdateOptions{}); err != nil {
			return err
		}
	}

	return nil
}
func (oe openshiftExtension) PostReconcile(context.Context, v1alpha1.TektonComponent) error {
	return nil
}
func (oe openshiftExtension) Finalize(context.Context, v1alpha1.TektonComponent) error {
	return nil
}

func SetDefault(properties *v1alpha1.TriggersProperties) bool {

	var updated = false

	// Set default service account as pipeline
	if properties.DefaultServiceAccount == "" {
		properties.DefaultServiceAccount = common.DefaultSA
		updated = true
	}
	return updated
}
