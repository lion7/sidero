// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package tests

import (
	"context"
	"testing"

	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/siderolabs/sidero/sfyra/pkg/capi"
	"github.com/siderolabs/sidero/sfyra/pkg/talos"
)

const (
	workloadClusterName   = "workload-cluster"
	workloadClusterLBPort = 20000
)

// TestWorkloadCluster deploys and destroys the workload cluster via CAPI.
func TestWorkloadCluster(ctx context.Context, metalClient client.Client, cluster talos.Cluster, capiManager *capi.Manager, talosRelease, kubernetesVersion string) TestFunc {
	return func(t *testing.T) {
		loadbalancer := deployCluster(ctx, t, metalClient, cluster, capiManager, workloadClusterName, serverClassName, workloadClusterLBPort, 1, 0, talosRelease, kubernetesVersion)
		defer loadbalancer.Close()

		deleteCluster(ctx, t, metalClient, workloadClusterName)
	}
}
