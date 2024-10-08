//go:build !ignore_autogenerated

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

// Code generated by controller-gen. DO NOT EDIT.

package v1beta1

import (
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AzureKeyVault) DeepCopyInto(out *AzureKeyVault) {
	*out = *in
	in.ClientSecret.DeepCopyInto(&out.ClientSecret)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AzureKeyVault.
func (in *AzureKeyVault) DeepCopy() *AzureKeyVault {
	if in == nil {
		return nil
	}
	out := new(AzureKeyVault)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AzureSecretSync) DeepCopyInto(out *AzureSecretSync) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AzureSecretSync.
func (in *AzureSecretSync) DeepCopy() *AzureSecretSync {
	if in == nil {
		return nil
	}
	out := new(AzureSecretSync)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *AzureSecretSync) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AzureSecretSyncList) DeepCopyInto(out *AzureSecretSyncList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]AzureSecretSync, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AzureSecretSyncList.
func (in *AzureSecretSyncList) DeepCopy() *AzureSecretSyncList {
	if in == nil {
		return nil
	}
	out := new(AzureSecretSyncList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *AzureSecretSyncList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AzureSecretSyncSpec) DeepCopyInto(out *AzureSecretSyncSpec) {
	*out = *in
	in.AzureKeyVault.DeepCopyInto(&out.AzureKeyVault)
	in.Github.DeepCopyInto(&out.Github)
	if in.Mappings != nil {
		in, out := &in.Mappings, &out.Mappings
		*out = make([]SecretMapping, len(*in))
		copy(*out, *in)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AzureSecretSyncSpec.
func (in *AzureSecretSyncSpec) DeepCopy() *AzureSecretSyncSpec {
	if in == nil {
		return nil
	}
	out := new(AzureSecretSyncSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *AzureSecretSyncStatus) DeepCopyInto(out *AzureSecretSyncStatus) {
	*out = *in
	in.LastSyncTime.DeepCopyInto(&out.LastSyncTime)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new AzureSecretSyncStatus.
func (in *AzureSecretSyncStatus) DeepCopy() *AzureSecretSyncStatus {
	if in == nil {
		return nil
	}
	out := new(AzureSecretSyncStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Github) DeepCopyInto(out *Github) {
	*out = *in
	in.Token.DeepCopyInto(&out.Token)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Github.
func (in *Github) DeepCopy() *Github {
	if in == nil {
		return nil
	}
	out := new(Github)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *SecretMapping) DeepCopyInto(out *SecretMapping) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new SecretMapping.
func (in *SecretMapping) DeepCopy() *SecretMapping {
	if in == nil {
		return nil
	}
	out := new(SecretMapping)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *SecretReference) DeepCopyInto(out *SecretReference) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new SecretReference.
func (in *SecretReference) DeepCopy() *SecretReference {
	if in == nil {
		return nil
	}
	out := new(SecretReference)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *SensitiveValueRef) DeepCopyInto(out *SensitiveValueRef) {
	*out = *in
	if in.ValueFromSecret != nil {
		in, out := &in.ValueFromSecret, &out.ValueFromSecret
		*out = new(SecretReference)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new SensitiveValueRef.
func (in *SensitiveValueRef) DeepCopy() *SensitiveValueRef {
	if in == nil {
		return nil
	}
	out := new(SensitiveValueRef)
	in.DeepCopyInto(out)
	return out
}
