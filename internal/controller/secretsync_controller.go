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

	corev1 "k8s.io/api/core/v1"

	"github.com/vishu42/github-secrets-operator/internal/encryption"
	"golang.org/x/oauth2"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azsecrets"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/google/go-github/v65/github"
	mainv1beta1 "github.com/vishu42/github-secrets-operator/api/v1beta1"
)

var (
	authCacheMap = sync.Map{}
)

// SecretSyncReconciler struct with the top-level index for CRDs and their associated secrets.
type SecretSyncReconciler struct {
	client.Client
	Scheme              *runtime.Scheme
	KeyVaultSecretIndex map[string]map[string]*SecretInfo // CRD reference -> Secret name -> SecretInfo

	// Add interfaces for external clients
	AzureClientFactory  AzureKeyVaultClientFactory
	GitHubClientFactory GitHubClientFactory
	Encrypter           encryption.Encrypter
}

type AzureKeyVaultClientFactory interface {
	NewClient(authData AzureAuthData) (AzureKeyVaultClient, error)
}

type GitHubClientFactory interface {
	NewClient(authData GitHubAuthData) (GitHubClient, error)
}

type AzureAuthData struct {
	TenantID     string
	ClientID     string
	ClientSecret string
	VaultName    string
}

type GitHubAuthData struct {
	Token       string
	Owner       string
	Repo        string
	SecretLevel string
	Environment string
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

type AzureKeyVaultClient interface {
	GetSecret(ctx context.Context, name string, version string, options *azsecrets.GetSecretOptions) (azsecrets.GetSecretResponse, error)
	// Add other methods as needed
}

type GitHubClient interface {
	// Add other methods as needed
	GithubActionsService
	GithubRepoService
}

type GithubActionsService interface {
	CreateOrUpdateOrgSecret(ctx context.Context, org string, eSecret *github.EncryptedSecret) (*github.Response, error)
	CreateOrUpdateRepoSecret(ctx context.Context, owner, repo string, eSecret *github.EncryptedSecret) (*github.Response, error)
	CreateOrUpdateEnvSecret(ctx context.Context, repoID int, env string, eSecret *github.EncryptedSecret) (*github.Response, error)
	GetOrgPublicKey(ctx context.Context, org string) (*github.PublicKey, *github.Response, error)
	GetRepoPublicKey(ctx context.Context, owner, repo string) (*github.PublicKey, *github.Response, error)
	GetEnvPublicKey(ctx context.Context, repoID int, env string) (*github.PublicKey, *github.Response, error)
	GetOrgSecret(ctx context.Context, org, name string) (*github.Secret, *github.Response, error)
	GetRepoSecret(ctx context.Context, owner, repo, name string) (*github.Secret, *github.Response, error)
	GetEnvSecret(ctx context.Context, repoID int, env, secretName string) (*github.Secret, *github.Response, error)
}

type GithubRepoService interface {
	Get(ctx context.Context, owner, repo string) (*github.Repository, *github.Response, error)
}

type RealAzureKeyVaultClientFactory struct{}

func (f *RealAzureKeyVaultClientFactory) NewClient(authData AzureAuthData) (AzureKeyVaultClient, error) {
	if authData == (AzureAuthData{}) {
		return nil, fmt.Errorf("nil auth data")
	}
	if authData.ClientID == "" {
		return nil, fmt.Errorf("client id is not present")
	}
	// Initialize the Azure Key Vault client
	cred, err := azidentity.NewClientSecretCredential(authData.TenantID, authData.ClientID, authData.ClientSecret, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to obtain a credential: %v", err)
	}

	vaultURI := fmt.Sprintf("https://%s.vault.azure.net/", authData.VaultName)
	client, err := azsecrets.NewClient(vaultURI, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create Azure Key Vault client: %v", err)
	}

	return &RealAzureKeyVaultClient{client: client}, nil
}

type RealAzureKeyVaultClient struct {
	client *azsecrets.Client
}

func (c *RealAzureKeyVaultClient) GetSecret(ctx context.Context, name string, version string, options *azsecrets.GetSecretOptions) (azsecrets.GetSecretResponse, error) {
	return c.client.GetSecret(ctx, name, version, nil)

}

type RealGitHubClientFactory struct{}

func (ghc *RealGitHubClientFactory) NewClient(authData GitHubAuthData) (GitHubClient, error) {
	token := authData.Token
	// Create GitHub client
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: token},
	)
	tc := oauth2.NewClient(context.Background(), ts)
	ghclient := github.NewClient(tc)

	return &RealGitHubClient{ghclient}, nil
}

type RealGitHubClient struct {
	client *github.Client
}

func (ghc *RealGitHubClient) CreateOrUpdateOrgSecret(ctx context.Context, org string, eSecret *github.EncryptedSecret) (*github.Response, error) {
	return ghc.client.Actions.CreateOrUpdateOrgSecret(ctx, org, eSecret)
}

func (ghc *RealGitHubClient) GetOrgSecret(ctx context.Context, org, name string) (*github.Secret, *github.Response, error) {
	return ghc.client.Actions.GetOrgSecret(ctx, org, name)
}

func (ghc *RealGitHubClient) CreateOrUpdateRepoSecret(ctx context.Context, owner, repo string, eSecret *github.EncryptedSecret) (*github.Response, error) {
	return ghc.client.Actions.CreateOrUpdateRepoSecret(ctx, owner, repo, eSecret)
}
func (ghc *RealGitHubClient) GetRepoSecret(ctx context.Context, owner, repo, name string) (*github.Secret, *github.Response, error) {
	return ghc.client.Actions.GetRepoSecret(ctx, owner, repo, name)
}

func (ghc *RealGitHubClient) CreateOrUpdateEnvSecret(ctx context.Context, repoID int, env string, eSecret *github.EncryptedSecret) (*github.Response, error) {
	return ghc.client.Actions.CreateOrUpdateEnvSecret(ctx, repoID, env, eSecret)
}

func (ghc *RealGitHubClient) GetEnvSecret(ctx context.Context, repoID int, env, secretName string) (*github.Secret, *github.Response, error) {
	return ghc.client.Actions.GetEnvSecret(ctx, repoID, env, secretName)
}

func (ghc *RealGitHubClient) Get(ctx context.Context, owner, repo string) (*github.Repository, *github.Response, error) {
	return ghc.client.Repositories.Get(ctx, owner, repo)
}

func (ghc *RealGitHubClient) GetOrgPublicKey(ctx context.Context, org string) (*github.PublicKey, *github.Response, error) {
	return ghc.client.Actions.GetOrgPublicKey(ctx, org)
}

func (ghc *RealGitHubClient) GetRepoPublicKey(ctx context.Context, owner, repo string) (*github.PublicKey, *github.Response, error) {
	return ghc.client.Actions.GetRepoPublicKey(ctx, owner, repo)
}

func (ghc *RealGitHubClient) GetEnvPublicKey(ctx context.Context, repoID int, env string) (*github.PublicKey, *github.Response, error) {
	return ghc.client.Actions.GetEnvPublicKey(ctx, repoID, env)
}

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

	// Extract sensitive values (ClientSecret and Token) from either direct value or Kubernetes Secret
	clientSecret, err := r.getSensitiveValue(ctx, secretSync.Spec.AzureKeyVault.ClientSecret, req.Namespace)
	if err != nil {
		log.Error(err, "unable to retrieve Azure Key Vault client secret")
		return ctrl.Result{}, err
	}

	githubToken, err := r.getSensitiveValue(ctx, secretSync.Spec.Github.Token, req.Namespace)
	if err != nil {
		log.Error(err, "unable to retrieve GitHub token")
		return ctrl.Result{}, err
	}

	// Extract authentication data from the CRD
	azureAuthData := AzureAuthData{
		TenantID:     secretSync.Spec.AzureKeyVault.TenantID,
		ClientID:     secretSync.Spec.AzureKeyVault.ClientID,
		ClientSecret: clientSecret,
		VaultName:    secretSync.Spec.AzureKeyVault.VaultName,
	}

	gitHubAuthData := GitHubAuthData{
		Token:       githubToken,
		Owner:       secretSync.Spec.Github.Owner,
		Repo:        secretSync.Spec.Github.Repo,
		SecretLevel: secretSync.Spec.Github.SecretLevel,
		Environment: secretSync.Spec.Github.Environment,
	}

	// Create clients using the factories
	azureClient, err := r.AzureClientFactory.NewClient(azureAuthData)
	if err != nil {
		log.Error(err, "failed to create Azure Key Vault client")
		return ctrl.Result{}, err
	}

	gitHubClient, err := r.GitHubClientFactory.NewClient(gitHubAuthData)
	if err != nil {
		log.Error(err, "failed to create GitHub client")
		return ctrl.Result{}, err
	}

	if r.KeyVaultSecretIndex == nil {
		r.KeyVaultSecretIndex = map[string]map[string]*SecretInfo{}
	}

	// Initialize the secret index for this specific CRD if not already present
	if _, exists := r.KeyVaultSecretIndex[req.NamespacedName.String()]; !exists {
		r.KeyVaultSecretIndex[req.NamespacedName.String()] = map[string]*SecretInfo{}
	}

	secretIndex := r.KeyVaultSecretIndex[req.NamespacedName.String()]

	// Iterate over the secret mappings in the CRD
	for _, mapping := range secretSync.Spec.Mappings {
		// Fetch secret from Azure Key Vault
		version := "" // Get the latest version
		azSecret, err := azureClient.GetSecret(ctx, mapping.KeyVaultSecret, version, nil)
		if err != nil {
			log.Error(err, fmt.Sprintf("failed to fetch secret %s from Azure Key Vault", mapping.KeyVaultSecret))
			continue
		}

		// Fetch GitHub public key and check if the secret already exists in GitHub
		existingSecret, _, err := r.getGitHubSecret(ctx, gitHubClient, mapping.GithubSecret, gitHubAuthData)
		if err != nil {
			log.Error(err, fmt.Sprintf("failed to fetch GitHub secret %s", mapping.GithubSecret))
			continue
		}

		// Compare last updated time if the secret exists in GitHub
		if existingSecret != nil {
			azureLastUpdated := azSecret.Attributes.Updated // This is the last updated time of the Azure secret
			gitHubLastUpdated := existingSecret.UpdatedAt   // Assume UpdatedAt gives us the last update timestamp in GitHub

			// Check if the GitHub secret is more up-to-date than the Azure secret
			if gitHubLastUpdated.After(*azureLastUpdated) {
				// The GitHub secret is more recent, so no need to update it
				log.Info("GitHub secret is already up to date, skipping update", "secret", mapping.GithubSecret)
				continue
			}
		}

		// Check if the secret exists in the index and if the update time is the same
		info, exists := secretIndex[mapping.KeyVaultSecret]
		if exists && info.LastUpdated != nil && info.LastUpdated.Equal(*azSecret.Attributes.Updated) {
			// Secret hasn't changed, skip syncing
			continue
		}

		// If the secret does not exist or is updated, update GitHub and the local index
		err = r.createOrUpdateGithubSecret(ctx, gitHubClient, secretSync, mapping, *azSecret.Value)
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
func (r *SecretSyncReconciler) getGitHubSecret(
	ctx context.Context,
	gitHubClient GitHubClient,
	secretName string,
	authData GitHubAuthData,
) (*github.Secret, *github.Response, error) {

	// Fetch the secret based on SecretLevel
	var existingSecret *github.Secret
	var resp *github.Response
	var err error

	switch authData.SecretLevel {
	case "org":
		existingSecret, resp, err = gitHubClient.GetOrgSecret(ctx, authData.Owner, secretName)

	case "repo":
		existingSecret, resp, err = gitHubClient.GetRepoSecret(ctx, authData.Owner, authData.Repo, secretName)
	case "environment":
		repo, resp, err := gitHubClient.Get(ctx, authData.Owner, authData.Repo)
		if err != nil {
			return nil, resp, err
		}
		existingSecret, resp, err = gitHubClient.GetEnvSecret(ctx, int(repo.GetID()), authData.Environment, secretName)
	default:
		err = fmt.Errorf("invalid secret level: %s", authData.SecretLevel)
	}

	return existingSecret, resp, err
}

// getSensitiveValue retrieves a sensitive value, either directly or from a Kubernetes Secret
func (r *SecretSyncReconciler) getSensitiveValue(ctx context.Context, sensitiveRef mainv1beta1.SensitiveValueRef, namespace string) (string, error) {
	// Check if the value is provided directly
	if sensitiveRef.Value != "" {
		return sensitiveRef.Value, nil
	}

	// If not, retrieve the value from the referenced Kubernetes Secret
	if sensitiveRef.ValueFromSecret != nil {
		secret := &corev1.Secret{}
		if err := r.Get(ctx, types.NamespacedName{
			Name:      sensitiveRef.ValueFromSecret.Name,
			Namespace: namespace,
		}, secret); err != nil {
			return "", fmt.Errorf("failed to retrieve secret %s: %w", sensitiveRef.ValueFromSecret.Name, err)
		}

		// Check if the key exists in the secret data
		secretData, exists := secret.Data[sensitiveRef.ValueFromSecret.Key]
		if !exists {
			return "", fmt.Errorf("key %s not found in secret %s", sensitiveRef.ValueFromSecret.Key, sensitiveRef.ValueFromSecret.Name)
		}

		return string(secretData), nil
	}

	return "", fmt.Errorf("no value or secret reference provided")
}

func (r *SecretSyncReconciler) getPublicKeyForSecretLevel(ctx context.Context, ghc GitHubClient,
	secretSync mainv1beta1.SecretSync) (*github.PublicKey, *github.Response, error) {
	switch secretSync.Spec.Github.SecretLevel {
	case "org":
		return ghc.GetOrgPublicKey(ctx, secretSync.Spec.Github.Owner)
	case "repo":
		return ghc.GetRepoPublicKey(ctx, secretSync.Spec.Github.Owner, secretSync.Spec.Github.Repo)
	case "environment":
		repo, _, err := ghc.Get(ctx, secretSync.Spec.Github.Owner, secretSync.Spec.Github.Repo)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to fetch GitHub repository details: %w", err)
		}
		return ghc.GetEnvPublicKey(ctx, int(repo.GetID()), secretSync.Spec.Github.Environment)
	default:
		return nil, nil, fmt.Errorf("invalid secret level: %s", secretSync.Spec.Github.SecretLevel)
	}
}

// createOrUpdateGithubSecret creates or updates a secret in GitHub at the specified level (org, repo, or environment).
func (r *SecretSyncReconciler) createOrUpdateGithubSecret(
	ctx context.Context,
	ghc GitHubClient,
	secretSync mainv1beta1.SecretSync,
	mapping mainv1beta1.SecretMapping,
	secretValue string,
) error {
	publicKey, _, err := r.getPublicKeyForSecretLevel(ctx, ghc, secretSync)
	if err != nil {
		return err
	}

	// Handle creating or updating the secret (repo/org/environment)
	switch secretSync.Spec.Github.SecretLevel {
	case "org":
		// Create or update organization-level secret
		encryptedSecret, err := r.Encrypter.EncryptSecretWithPublicKey(publicKey, mapping.GithubSecret, secretValue)
		if err != nil {
			return fmt.Errorf("failed encrypt secret: %v", err)
		}
		_, err = ghc.CreateOrUpdateOrgSecret(ctx, secretSync.Spec.Github.Owner, encryptedSecret)
		if err != nil {
			return fmt.Errorf("failed to create or update GitHub organization secret: %v", err)
		}

	case "repo":
		// Create or update repository-level secret
		encryptedSecret, err := r.Encrypter.EncryptSecretWithPublicKey(publicKey, mapping.GithubSecret, secretValue)
		if err != nil {
			return fmt.Errorf("failed encrypt secret: %v", err)
		}
		_, err = ghc.CreateOrUpdateRepoSecret(
			ctx,
			secretSync.Spec.Github.Owner,
			secretSync.Spec.Github.Repo,
			encryptedSecret,
		)
		if err != nil {
			return fmt.Errorf("failed to create or update GitHub repository secret: %v", err)
		}

	case "environment":
		repo, _, err := ghc.Get(ctx, secretSync.Spec.Github.Owner, secretSync.Spec.Github.Repo)
		if err != nil {
			return fmt.Errorf("failed to fetch GitHub repository details: %w", err)
		}
		// Create or update environment-level secret using the repo ID
		encryptedSecret, err := r.Encrypter.EncryptSecretWithPublicKey(publicKey, mapping.GithubSecret, secretValue)
		if err != nil {
			return fmt.Errorf("failed encrypt secret: %v", err)
		}
		_, err = ghc.CreateOrUpdateEnvSecret(
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
	return ctrl.NewControllerManagedBy(mgr).
		For(&mainv1beta1.SecretSync{}).
		Complete(r)
}

// TODO: get them from secrets
// Generates azsecret and github clients for each CRD
// Stores them in the authmap with namespacedname as key
// Uses cached clients if already authenticated
// func ServiceClient(namespacedName types.NamespacedName, githubToken, tenantId, clientId, clientSecret, vaultName string) (*AuthCache, error) {
// 	vaultURI := fmt.Sprintf("https://%s.vault.azure.net/", vaultName)

// 	authcache, ok := authCacheMap.Load(namespacedName)
// 	if !ok {
// 		// Cache not found, generate new client
// 		cred, err := azidentity.NewClientSecretCredential(tenantId, clientId, clientSecret, nil)
// 		l.Println("tenantId", tenantId)
// 		l.Println("clientId", clientId)
// 		l.Println("clientsecret", clientSecret)
// 		if err != nil {
// 			return nil, fmt.Errorf("failed to obtain a credential: %v", err)
// 		}

// 		// Connect to Azure Key Vault
// 		azclient, err := azsecrets.NewClient(vaultURI, cred, nil)
// 		if err != nil {
// 			return nil, fmt.Errorf("failed to create Azure Key Vault client: %v", err)
// 		}

// 		// Create GitHub client
// 		ts := oauth2.StaticTokenSource(
// 			&oauth2.Token{AccessToken: githubToken},
// 		)
// 		tc := oauth2.NewClient(context.Background(), ts)
// 		ghclient := github.NewClient(tc)

// 		authcache = &AuthCache{AzSecretsClient: azclient, GithubClient: ghclient}
// 		authCacheMap.Store(namespacedName, authcache)
// 	}

// 	// Return cached clients
// 	return authcache.(*AuthCache), nil
// }
