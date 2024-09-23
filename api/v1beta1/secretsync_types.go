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

// SecretSyncSpec defines the desired state of SecretSync
type SecretSyncSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// Azure Key Vault information
	AzureKeyVault AzureKeyVault `json:"azureKeyVault,omitempty"`
	// GitHub repository information
	Github Github `json:"github,omitempty"`
	// Mappings between Key Vault secrets and GitHub secrets
	Mappings []SecretMapping `json:"mappings,omitempty"`
}

// AzureKeyVault contains information to connect to Azure Key Vault
type AzureKeyVault struct {
	VaultName string `json:"vaultName"`
}

// Github contains information for the GitHub repository
type Github struct {
	RepoName         string `json:"repoName,omitempty"`
	Environment      string `json:"environment,omitempty"`
	OrganizationName string `json:"organizationName,omitempty"`
}

// SecretMapping defines the mapping from Key Vault to GitHub
type SecretMapping struct {
	KeyVaultSecret string `json:"keyVaultSecret"`
	GithubSecret   string `json:"githubSecret"`
}

// SecretSyncStatus defines the observed state of SecretSync
type SecretSyncStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// Add status fields here, such as sync status or last sync time
	LastSyncTime metav1.Time `json:"lastSyncTime,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// SecretSync is the Schema for the secretsyncs API
type SecretSync struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   SecretSyncSpec   `json:"spec,omitempty"`
	Status SecretSyncStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// SecretSyncList contains a list of SecretSync
type SecretSyncList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SecretSync `json:"items"`
}

func init() {
	SchemeBuilder.Register(&SecretSync{}, &SecretSyncList{})
}
