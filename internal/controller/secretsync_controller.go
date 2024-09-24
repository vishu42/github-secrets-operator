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
	"sync"
	"time"

	l "log"

	"github.com/vishu42/github-secrets-operator/internal/encryption"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azsecrets"
	"golang.org/x/oauth2"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/google/go-github/v65/github"
	mainv1beta1 "github.com/vishu42/github-secrets-operator/api/v1beta1"
)

// SecretSyncReconciler struct with the top-level index for CRDs and their associated secrets.
type SecretSyncReconciler struct {
	client.Client
	Scheme              *runtime.Scheme
	KeyVaultSecretIndex map[string]map[string]*SecretInfo // CRD reference -> Secret name -> SecretInfo
}

// SecretInfo holds the necessary details about a secret, including its value, update time, and CRD reference.
type SecretInfo struct {
	Value          string               // The actual secret value from Azure Key Vault
	LastUpdated    *time.Time           // The last update time of the secret in Azure Key Vault
	ExistsInGithub bool                 // Whether the secret exists in GitHub or not
	CRDRef         types.NamespacedName // Reference to the CRD managing this secret (namespace and name)
}

type AuthCache struct {
	AzSecretsClient *azsecrets.Client
	GithubClient    *github.Client
}

var (
	authCacheMap = sync.Map{}
)

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

	// Fetch the SecretSync instance (CRD)
	var secretSync mainv1beta1.SecretSync
	if err := r.Get(ctx, req.NamespacedName, &secretSync); err != nil {
		log.Error(err, "unable to fetch SecretSync")
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Fetch the Azure Key Vault and GitHub clients for the specific CRD
	ac, err := ServiceClient(
		req.NamespacedName,
		secretSync.Spec.Github.Token,
		secretSync.Spec.AzureKeyVault.TenantID,
		secretSync.Spec.AzureKeyVault.ClientID,
		secretSync.Spec.AzureKeyVault.ClientSecret,
		secretSync.Spec.AzureKeyVault.VaultName,
	)
	if err != nil {
		log.Error(err, "")
		return ctrl.Result{}, fmt.Errorf("failed to authenticate with Azure Key Vault or GitHub - %w", err)
	}

	// Initialize the secret index for this specific CRD if not already present
	if _, exists := r.KeyVaultSecretIndex[req.NamespacedName.String()]; !exists {
		r.KeyVaultSecretIndex[req.NamespacedName.String()] = make(map[string]*SecretInfo)
	}

	secretIndex := r.KeyVaultSecretIndex[req.NamespacedName.String()]

	// Iterate over the secret mappings in the CRD
	for _, mapping := range secretSync.Spec.Mappings {
		// Fetch secret from Azure Key Vault
		version := "" // Get the latest version
		azSecret, err := ac.AzSecretsClient.GetSecret(ctx, mapping.KeyVaultSecret, version, nil)
		if err != nil {
			log.Error(err, fmt.Sprintf("failed to fetch secret %s from Azure Key Vault", mapping.KeyVaultSecret))
			continue
		}

		// Check if the secret exists in the index and if the update time is the same
		info, exists := secretIndex[mapping.KeyVaultSecret]
		if exists && info.LastUpdated != nil && info.LastUpdated.Equal(*azSecret.Attributes.Updated) {
			// Secret hasn't changed, skip syncing
			continue
		}

		// If the secret does not exist or is updated, update GitHub and the local index
		err = r.createOrUpdateGithubSecret(ctx, ac, secretSync, mapping, *azSecret.Value)
		if err != nil {
			log.Error(err, fmt.Sprintf("failed to sync GitHub secret: %s", mapping.GithubSecret))
			continue
		}

		// Update the index with the new secret info
		secretIndex[mapping.KeyVaultSecret] = &SecretInfo{
			Value:          *azSecret.Value,
			LastUpdated:    azSecret.Attributes.Updated,
			ExistsInGithub: true,
			CRDRef:         req.NamespacedName,
		}
	}

	// Requeue after 10 minutes for the next reconciliation
	return ctrl.Result{RequeueAfter: 10 * time.Minute}, nil
}

func (r *SecretSyncReconciler) getPublicKeyForSecretLevel(ctx context.Context, ac *AuthCache, secretSync mainv1beta1.SecretSync) (*github.PublicKey, *github.Response, error) {
	switch secretSync.Spec.Github.SecretLevel {
	case "org":
		return ac.GithubClient.Actions.GetOrgPublicKey(ctx, secretSync.Spec.Github.Owner)
	case "repo":
		return ac.GithubClient.Actions.GetRepoPublicKey(ctx, secretSync.Spec.Github.Owner, secretSync.Spec.Github.Repo)
	case "environment":
		repo, _, err := ac.GithubClient.Repositories.Get(ctx, secretSync.Spec.Github.Owner, secretSync.Spec.Github.Repo)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to fetch GitHub repository details: %w", err)
		}
		return ac.GithubClient.Actions.GetEnvPublicKey(ctx, int(repo.GetID()), secretSync.Spec.Github.Environment)
	default:
		return nil, nil, fmt.Errorf("invalid secret level: %s", secretSync.Spec.Github.SecretLevel)
	}
}

// createOrUpdateGithubSecret creates or updates a secret in GitHub at the specified level (org, repo, or environment).
func (r *SecretSyncReconciler) createOrUpdateGithubSecret(
	ctx context.Context,
	ac *AuthCache,
	secretSync mainv1beta1.SecretSync,
	mapping mainv1beta1.SecretMapping,
	secretValue string,
) error {
	publicKey, _, err := r.getPublicKeyForSecretLevel(ctx, ac, secretSync)
	if err != nil {
		return err
	}

	// Handle creating or updating the secret (repo/org/environment)
	switch secretSync.Spec.Github.SecretLevel {
	case "org":
		// Create or update organization-level secret
		encryptedSecret, err := encryption.EncryptSecretWithPublicKey(publicKey, mapping.GithubSecret, secretValue)
		if err != nil {
			return fmt.Errorf("failed encrypt secret: %v", err)
		}
		_, err = ac.GithubClient.Actions.CreateOrUpdateOrgSecret(ctx, secretSync.Spec.Github.Owner, encryptedSecret)
		if err != nil {
			return fmt.Errorf("failed to create or update GitHub organization secret: %v", err)
		}

	case "repo":
		// Create or update repository-level secret
		encryptedSecret, err := encryption.EncryptSecretWithPublicKey(publicKey, mapping.GithubSecret, secretValue)
		if err != nil {
			return fmt.Errorf("failed encrypt secret: %v", err)
		}
		_, err = ac.GithubClient.Actions.CreateOrUpdateRepoSecret(
			ctx,
			secretSync.Spec.Github.Owner,
			secretSync.Spec.Github.Repo,
			encryptedSecret,
		)
		if err != nil {
			return fmt.Errorf("failed to create or update GitHub repository secret: %v", err)
		}

	case "environment":
		repo, _, err := ac.GithubClient.Repositories.Get(ctx, secretSync.Spec.Github.Owner, secretSync.Spec.Github.Repo)
		if err != nil {
			return fmt.Errorf("failed to fetch GitHub repository details: %w", err)
		}
		// Create or update environment-level secret using the repo ID
		encryptedSecret, err := encryption.EncryptSecretWithPublicKey(publicKey, mapping.GithubSecret, secretValue)
		if err != nil {
			return fmt.Errorf("failed encrypt secret: %v", err)
		}
		_, err = ac.GithubClient.Actions.CreateOrUpdateEnvSecret(
			ctx,
			int(repo.GetID()), // Using the repo ID
			secretSync.Spec.Github.Environment,
			encryptedSecret,
		)
		if err != nil {
			return fmt.Errorf("failed to create or update GitHub environment secret: %v", err)
		}

	default:
		return fmt.Errorf("invalid secret level: %s", secretSync.Spec.Github.SecretLevel)
	}

	l.Printf("Secret %s has been successfully synced to GitHub at %s level", mapping.GithubSecret, secretSync.Spec.Github.SecretLevel)
	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *SecretSyncReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.KeyVaultSecretIndex = make(map[string]map[string]*SecretInfo)
	return ctrl.NewControllerManagedBy(mgr).
		For(&mainv1beta1.SecretSync{}).
		Complete(r)
}

// TODO: get them from secrets
// Generates azsecret and github clients for each CRD
// Stores them in the authmap with namespacedname as key
// Uses cached clients if already authenticated
func ServiceClient(namespacedName types.NamespacedName, githubToken, tenantId, clientId, clientSecret, vaultName string) (*AuthCache, error) {
	vaultURI := fmt.Sprintf("https://%s.vault.azure.net/", vaultName)

	authcache, ok := authCacheMap.Load(namespacedName)
	if !ok {
		// Cache not found, generate new client
		cred, err := azidentity.NewClientSecretCredential(tenantId, clientId, clientSecret, nil)
		l.Println("tenantId", tenantId)
		l.Println("clientId", clientId)
		l.Println("clientsecret", clientSecret)
		if err != nil {
			return nil, fmt.Errorf("failed to obtain a credential: %v", err)
		}

		// Connect to Azure Key Vault
		azclient, err := azsecrets.NewClient(vaultURI, cred, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create Azure Key Vault client: %v", err)
		}

		// Create GitHub client
		ts := oauth2.StaticTokenSource(
			&oauth2.Token{AccessToken: githubToken},
		)
		tc := oauth2.NewClient(context.Background(), ts)
		ghclient := github.NewClient(tc)

		authcache = &AuthCache{AzSecretsClient: azclient, GithubClient: ghclient}
		authCacheMap.Store(namespacedName, authcache)
	}

	// Return cached clients
	return authcache.(*AuthCache), nil
}
