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

package v1beta1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// AzureSecretSyncSpec defines the desired state of SecretSync
type AzureSecretSyncSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// Azure Key Vault information
	AzureKeyVault AzureKeyVault `json:"azureKeyVault"`
	// GitHub repository information
	Github Github `json:"github"`
	// Mappings between Key Vault secrets and GitHub secrets
	Mappings []SecretMapping `json:"mappings,omitempty"`
}

// AzureKeyVault contains information to connect to Azure Key Vault
type AzureKeyVault struct {
	VaultName    string            `json:"vaultName"`
	TenantID     string            `json:"tenantId"`
	ClientID     string            `json:"clientId"`
	ClientSecret SensitiveValueRef `json:"clientSecret"` // Supports both literal and secret reference
}

// SensitiveValueRef allows specifying a sensitive value directly or referencing a Kubernetes secret
type SensitiveValueRef struct {
	// Value can be provided directly in the spec (literal value)
	Value string `json:"value,omitempty"`
	// Refers to a Kubernetes secret in the same namespace
	ValueFromSecret *SecretReference `json:"valueFromSecret,omitempty"`
}

// SecretReference defines a reference to a key within a Kubernetes secret
type SecretReference struct {
	// Name of the secret
	Name string `json:"name"`
	// Key within the secret to retrieve the value from
	Key string `json:"key"`
}

// Github contains information for the GitHub repository
type Github struct {
	Token       SensitiveValueRef `json:"token"`
	Owner       string            `json:"owner"`
	SecretLevel string            `json:"secretLevel"`           // Can be "repo", "org", or "environment"
	Environment string            `json:"environment,omitempty"` // Optional, used for env-level secrets
	Repo        string            `json:"repo,omitempty"`        // Optional, used for repo-level and env-level secrets
}

// SecretMapping defines the mapping from Key Vault to GitHub
type SecretMapping struct {
	KeyVaultSecret string `json:"keyVaultSecret"`
	GithubSecret   string `json:"githubSecret"`
}

// AzureSecretSyncStatus defines the observed state of SecretSync
type AzureSecretSyncStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// Add status fields here, such as sync status or last sync time
	LastSyncTime metav1.Time `json:"lastSyncTime,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// AzureSecretSync is the Schema for the secretsyncs API
type AzureSecretSync struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AzureSecretSyncSpec   `json:"spec,omitempty"`
	Status AzureSecretSyncStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// AzureSecretSyncList contains a list of SecretSync
type AzureSecretSyncList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AzureSecretSync `json:"items"`
}

func init() {
	SchemeBuilder.Register(&AzureSecretSync{}, &AzureSecretSyncList{})
}
