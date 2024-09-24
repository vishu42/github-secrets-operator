/*
Copyright 2024.

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

package controller

import (
	"context"
	"fmt"
	l "log"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azsecrets"
	"golang.org/x/oauth2"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/google/go-github/github"

	mainv1beta1 "github.com/vishu42/github-secrets-operator/api/v1beta1"
)

// SecretSyncReconciler reconciles a SecretSync object
type SecretSyncReconciler struct {
	client.Client
	Scheme              *runtime.Scheme
	KeyVaultSecretIndex map[string]*time.Time
}

type AuthCache struct {
	AzSecretsClient *azsecrets.Client
	GithubClient    *github.Client
}

var authCacheMap = sync.Map{}

// +kubebuilder:rbac:groups=main.vishu42.github.io,resources=secretsyncs,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=main.vishu42.github.io,resources=secretsyncs/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=main.vishu42.github.io,resources=secretsyncs/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the SecretSync object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.19.0/pkg/reconcile
func (r *SecretSyncReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	// TODO(user): your logic here
	fmt.Println("reconciling......")

	// Fetch the SecretSync instance
	var secretSync mainv1beta1.SecretSync
	if err := r.Get(ctx, req.NamespacedName, &secretSync); err != nil {
		log.Error(err, "unable to fetch SecretSync")
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	ac, err := ServiceClient(req.NamespacedName, secretSync.Spec.Github.Token, secretSync.Spec.AzureKeyVault.TenantID, secretSync.Spec.AzureKeyVault.ClientID, secretSync.Spec.AzureKeyVault.ClientSecret, secretSync.Spec.AzureKeyVault.VaultName)
	if err != nil {
		return ctrl.Result{}, err
	}

	// // iterate over secrets in spec
	// for i := range secretSync.Spec.Mappings {
	// 	secret := secretSync.Spec.Mappings[i]

	// 	// fetch azure key vault secret
	// 	version := ""
	// 	resp, err := r.AzureClient.GetSecret(context.TODO(), secret.KeyVaultSecret, version, nil)
	// 	if err != nil {
	// 		l.Fatalf("failed to get the secret: %v", err)
	// 	}

	// 	// add secret to index if it doesnt exist already
	// 	_, ok := r.KeyVaultSecretIndex[secret.KeyVaultSecret]
	// 	if !ok {
	// 		r.KeyVaultSecretIndex[secret.KeyVaultSecret] = resp.Attributes.Updated
	// 	}

	// 	// if lastUpdateTime doesnt match with fetched lastupdatetime
	// 	if resp.Attributes.Updated != r.KeyVaultSecretIndex[secret.KeyVaultSecret] {
	// 		// set secret to github repo

	// 	}

	// 	// if secret is not in map
	// 	// - fetch secret and add it to map
	// 	// else
	// 	// fetch secret and compare its updated to updated in map

	// 	secretIndex[secret.KeyVaultSecret] = resp.Attributes.Updated

	// }

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *SecretSyncReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.KeyVaultSecretIndex = make(map[string]*time.Time)

	return ctrl.NewControllerManagedBy(mgr).
		For(&mainv1beta1.SecretSync{}).
		Complete(r)
}

// TODO: get them from secrets
// Generates azsecret and github clients
// stores them in the authmap with namespacedname as key
// checks if the client is present for a namespacedname and if it does checks its validity and if its valid return that token instead of trying to fetch a new one
func ServiceClient(namespacedName types.NamespacedName, githubToken, tenantId, clientId, clientSecret, vaultName string) (*AuthCache, error) {
	vaultURI := fmt.Sprintf("https://%s.vault.azure.net/", vaultName)

	authcache, ok := authCacheMap.Load(namespacedName)
	if !ok {
		// cache not found
		// generate new client
		cred, err := azidentity.NewClientSecretCredential(tenantId, clientId, clientSecret, nil)
		if err != nil {
			l.Fatalf("failed to obtain a credential: %v", err)
		}

		// Establish a connection to the Key Vault client
		azclient, err := azsecrets.NewClient(vaultURI, cred, nil)

		// github client
		ts := oauth2.StaticTokenSource(
			&oauth2.Token{AccessToken: githubToken},
		)
		tc := oauth2.NewClient(context.Background(), ts)
		ghclient := github.NewClient(tc)
		authcache = &AuthCache{azclient, ghclient}
		authCacheMap.Store(namespacedName, authcache)
	}

	// cache found
	// use cache

	return authcache.(*AuthCache), nil
}