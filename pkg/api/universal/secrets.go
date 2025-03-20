/*
Copyright 2022 The Dapr Authors
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

package universal

import (
	"context"
	"fmt"
	"time"

	"github.com/dapr/components-contrib/secretstores"
	diag "github.com/dapr/dapr/pkg/diagnostics"
	"github.com/dapr/dapr/pkg/messages"
	runtimev1pb "github.com/dapr/dapr/pkg/proto/runtime/v1"
	"github.com/dapr/dapr/pkg/resiliency"
)

func (a *Universal) GetSecret(ctx context.Context, in *runtimev1pb.GetSecretRequest) (*runtimev1pb.GetSecretResponse, error) {
	var response *runtimev1pb.GetSecretResponse

	component, err := a.secretsValidateRequest(in.GetStoreName())
	if err != nil {
		return response, err
	}

	if !a.isSecretAllowed(in.GetStoreName(), in.GetKey()) {
		config, ok := a.compStore.GetSecretsConfiguration(in.GetStoreName())
		err = messages.ErrSecretPermissionDenied.WithFormat(in.GetKey(), in.GetStoreName())

		if ok {
			_, reason := config.IsSecretAllowedWithReason(in.GetKey())
			a.logger.Infof("Secret access denied. Key: %s, Store: %s, Reason: %s, DefaultAccess: %s, AllowedSecrets: %v, DeniedSecrets: %v",
				in.GetKey(), in.GetStoreName(), reason, config.DefaultAccess,
				config.AllowedSecrets, config.DeniedSecrets)
		} else {
			a.logger.Infof("Secret access denied. Key: %s, Store: %s, No scoping configuration found",
				in.GetKey(), in.GetStoreName())
		}
		return response, err
	}

	req := secretstores.GetSecretRequest{
		Name:     in.GetKey(),
		Metadata: in.GetMetadata(),
	}

	start := time.Now()
	policyRunner := resiliency.NewRunner[*secretstores.GetSecretResponse](ctx,
		a.resiliency.ComponentOutboundPolicy(in.GetStoreName(), resiliency.Secretstore),
	)
	getResponse, err := policyRunner(func(ctx context.Context) (*secretstores.GetSecretResponse, error) {
		rResp, rErr := component.GetSecret(ctx, req)
		return &rResp, rErr
	})
	elapsed := diag.ElapsedSince(start)

	diag.DefaultComponentMonitoring.SecretInvoked(ctx, in.GetStoreName(), diag.Get, err == nil, elapsed)

	if err != nil {
		err = messages.ErrSecretGet.WithFormat(req.Name, in.GetStoreName(), err.Error())
		a.logger.Debug(err)
		return response, err
	}

	if getResponse != nil {
		response = &runtimev1pb.GetSecretResponse{
			Data: getResponse.Data,
		}
	}
	return response, nil
}

func (a *Universal) GetBulkSecret(ctx context.Context, in *runtimev1pb.GetBulkSecretRequest) (*runtimev1pb.GetBulkSecretResponse, error) {
	var response *runtimev1pb.GetBulkSecretResponse

	component, err := a.secretsValidateRequest(in.GetStoreName())
	if err != nil {
		return response, err
	}

	req := secretstores.BulkGetSecretRequest{
		Metadata: in.GetMetadata(),
	}

	start := time.Now()
	policyRunner := resiliency.NewRunner[*secretstores.BulkGetSecretResponse](ctx,
		a.resiliency.ComponentOutboundPolicy(in.GetStoreName(), resiliency.Secretstore),
	)
	getResponse, err := policyRunner(func(ctx context.Context) (*secretstores.BulkGetSecretResponse, error) {
		rResp, rErr := component.BulkGetSecret(ctx, req)
		return &rResp, rErr
	})
	elapsed := diag.ElapsedSince(start)

	diag.DefaultComponentMonitoring.SecretInvoked(ctx, in.GetStoreName(), diag.BulkGet, err == nil, elapsed)

	if err != nil {
		err = messages.ErrBulkSecretGet.WithFormat(in.GetStoreName(), err.Error())
		a.logger.Debug(err)
		return response, err
	}

	if getResponse == nil {
		return response, nil
	}
	filteredSecrets := map[string]map[string]string{}
	var deniedSecrets []string
	var deniedSecretReasons []string

	for key, v := range getResponse.Data {
		if a.isSecretAllowed(in.GetStoreName(), key) {
			filteredSecrets[key] = v
		} else {
			deniedSecrets = append(deniedSecrets, key)
			if config, ok := a.compStore.GetSecretsConfiguration(in.GetStoreName()); ok {
				_, reason := config.IsSecretAllowedWithReason(key)
				deniedSecretReasons = append(deniedSecretReasons,
					fmt.Sprintf("%s: %s", key, reason))
			}
			a.logger.Debugf(messages.ErrSecretPermissionDenied.WithFormat(key, in.GetStoreName()).String())
		}
	}

	if len(deniedSecrets) > 0 {
		config, ok := a.compStore.GetSecretsConfiguration(in.GetStoreName())
		if ok {
			a.logger.Infof("Some secrets were denied access. Store: %s, DefaultAccess: %s, Denied keys with reasons: %v",
				in.GetStoreName(), config.DefaultAccess, deniedSecretReasons)
		} else {
			a.logger.Infof("Some secrets were denied access. Store: %s, No scoping configuration found. Denied keys: %v",
				in.GetStoreName(), deniedSecrets)
		}
	}

	if getResponse.Data != nil {
		response = &runtimev1pb.GetBulkSecretResponse{
			Data: make(map[string]*runtimev1pb.SecretResponse, len(filteredSecrets)),
		}
		for key, v := range filteredSecrets {
			response.Data[key] = &runtimev1pb.SecretResponse{Secrets: v}
		}
	}
	return response, nil
}

// Internal method that checks if the request is for a valid secret store component.
func (a *Universal) secretsValidateRequest(componentName string) (secretstores.SecretStore, error) {
	if a.compStore.SecretStoresLen() == 0 {
		err := messages.ErrSecretStoreNotConfigured
		a.logger.Debug(err)
		return nil, err
	}

	component, ok := a.compStore.GetSecretStore(componentName)
	if !ok {
		err := messages.ErrSecretStoreNotFound.WithFormat(componentName)
		a.logger.Debug(err)
		return nil, err
	}

	return component, nil
}

func (a *Universal) isSecretAllowed(storeName, key string) bool {
	if config, ok := a.compStore.GetSecretsConfiguration(storeName); ok {
		allowed, reason := config.IsSecretAllowedWithReason(key)
		if !allowed {
			a.logger.Infof("Secret access denied. Key: %s, Store: %s, Reason: %s, DefaultAccess: %s, "+
				"AllowedSecrets: %v, DeniedSecrets: %v",
				key, storeName, reason, config.DefaultAccess,
				config.AllowedSecrets, config.DeniedSecrets)
		}
		return allowed
	}
	// By default, if a configuration is not defined for a secret store, return true.
	a.logger.Debugf("No secret scoping configuration found for store %s, defaulting to allow access for key %s",
		storeName, key)
	return true
}
