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
	"net/http"

	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azsecrets"
	"github.com/google/go-github/v65/github"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	mainv1beta1 "github.com/vishu42/github-secrets-operator/api/v1beta1"
)

var (
	keyId string = "mock-key-id"
	key   string = "mock-key"
)

type MockAzureKeyVaultClientFactory struct{}

func (f *MockAzureKeyVaultClientFactory) NewClient(authData AzureAuthData) (AzureKeyVaultClient, error) {
	return &MockAzureKeyVaultClient{}, nil
}

type MockAzureKeyVaultClient struct{}

func (c *MockAzureKeyVaultClient) GetSecret(ctx context.Context, name string, version string, options *azsecrets.GetSecretOptions) (azsecrets.GetSecretResponse, error) {
	return azsecrets.GetSecretResponse{}, nil
}

type MockGitHubClientFactory struct{}

func (f *MockGitHubClientFactory) NewClient(authData GitHubAuthData) (GitHubClient, error) {
	return &MockGitHubClient{}, nil
}

type MockGitHubClient struct{}

// Mock CreateOrUpdateEnvSecret
func (m *MockGitHubClient) CreateOrUpdateEnvSecret(ctx context.Context, repoID int, env string, eSecret *github.EncryptedSecret) (*github.Response, error) {
	// Simulate successful creation or update
	return &github.Response{Response: &http.Response{StatusCode: http.StatusOK}}, nil
}

// Mock CreateOrUpdateOrgSecret
func (m *MockGitHubClient) CreateOrUpdateOrgSecret(ctx context.Context, org string, eSecret *github.EncryptedSecret) (*github.Response, error) {
	// Simulate successful creation or update
	return &github.Response{Response: &http.Response{StatusCode: http.StatusOK}}, nil
}

// Mock CreateOrUpdateRepoSecret
func (m *MockGitHubClient) CreateOrUpdateRepoSecret(ctx context.Context, owner string, repo string, eSecret *github.EncryptedSecret) (*github.Response, error) {
	// Simulate successful creation or update
	return &github.Response{Response: &http.Response{StatusCode: http.StatusOK}}, nil
}

// Mock Get (for repository information)
func (m *MockGitHubClient) Get(ctx context.Context, owner string, repo string) (*github.Repository, *github.Response, error) {
	// Simulate fetching repository information
	repoMock := &github.Repository{ID: github.Int64(12345), Name: github.String(repo)}
	return repoMock, &github.Response{Response: &http.Response{StatusCode: http.StatusOK}}, nil
}

// Mock GetEnvPublicKey
func (m *MockGitHubClient) GetEnvPublicKey(ctx context.Context, repoID int, env string) (*github.PublicKey, *github.Response, error) {
	// Simulate fetching environment public key
	pubKey := &github.PublicKey{KeyID: &keyId, Key: &key}
	return pubKey, &github.Response{Response: &http.Response{StatusCode: http.StatusOK}}, nil
}

// Mock GetOrgPublicKey
func (m *MockGitHubClient) GetOrgPublicKey(ctx context.Context, org string) (*github.PublicKey, *github.Response, error) {
	// Simulate fetching organization public key
	pubKey := &github.PublicKey{KeyID: &keyId, Key: &key}
	return pubKey, &github.Response{Response: &http.Response{StatusCode: http.StatusOK}}, nil
}

// Mock GetRepoPublicKey
func (m *MockGitHubClient) GetRepoPublicKey(ctx context.Context, owner string, repo string) (*github.PublicKey, *github.Response, error) {
	// Simulate fetching repository public key
	pubKey := &github.PublicKey{KeyID: &keyId, Key: &key}
	return pubKey, &github.Response{Response: &http.Response{StatusCode: http.StatusOK}}, nil
}

var _ = Describe("SecretSync Controller", func() {
	Context("When reconciling a resource", func() {
		const resourceName = "test-resource"

		ctx := context.Background()

		typeNamespacedName := types.NamespacedName{
			Name:      resourceName,
			Namespace: "default", // TODO(user):Modify as needed
		}
		secretsync := &mainv1beta1.SecretSync{}

		BeforeEach(func() {
			By("creating the custom resource for the Kind SecretSync")
			err := k8sClient.Get(ctx, typeNamespacedName, secretsync)
			if err != nil && errors.IsNotFound(err) {
				resource := &mainv1beta1.SecretSync{
					ObjectMeta: metav1.ObjectMeta{
						Name:      resourceName,
						Namespace: "default",
					},
					// TODO(user): Specify other spec details if needed.
				}
				Expect(k8sClient.Create(ctx, resource)).To(Succeed())
			}
		})

		AfterEach(func() {
			// TODO(user): Cleanup logic after each test, like removing the resource instance.
			resource := &mainv1beta1.SecretSync{}
			err := k8sClient.Get(ctx, typeNamespacedName, resource)
			Expect(err).NotTo(HaveOccurred())

			By("Cleanup the specific resource instance SecretSync")
			Expect(k8sClient.Delete(ctx, resource)).To(Succeed())
		})
		It("should successfully reconcile the resource", func() {
			By("Reconciling the created resource")
			fmt.Println("checkpoint1")

			controllerReconciler := &SecretSyncReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			var err error
			// Capture the logs printed during reconcile execution

			_, err = controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})

			fmt.Println("checkpoint2")

			Expect(err).To(MatchError("nil azure client factory"))
			// TODO(user): Add more specific assertions depending on your controller's reconciliation logic.
			// Example: If you expect a certain status condition after reconciliation, verify it here.
		})
	})
})
