/*
Copyright 2023 The Dapr Authors
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
	"bytes"
	"context"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/dapr/components-contrib/secretstores"
	"github.com/dapr/dapr/pkg/config"
	"github.com/dapr/dapr/pkg/messages"
	runtimev1pb "github.com/dapr/dapr/pkg/proto/runtime/v1"
	"github.com/dapr/dapr/pkg/resiliency"
	"github.com/dapr/dapr/pkg/runtime/compstore"
	daprt "github.com/dapr/dapr/pkg/testing"
	"github.com/dapr/kit/logger"
)

// CustomSecretStore implements secretstores.SecretStore for testing
type CustomSecretStore struct {
	daprt.FakeSecretStore
	bulkSecrets map[string]map[string]string
}

func (c CustomSecretStore) GetSecret(ctx context.Context, req secretstores.GetSecretRequest) (secretstores.GetSecretResponse, error) {
	// Inherit from FakeSecretStore for normal GetSecret
	return c.FakeSecretStore.GetSecret(ctx, req)
}

func (c CustomSecretStore) BulkGetSecret(ctx context.Context, req secretstores.BulkGetSecretRequest) (secretstores.BulkGetSecretResponse, error) {
	return secretstores.BulkGetSecretResponse{
		Data: c.bulkSecrets,
	}, nil
}

func (c CustomSecretStore) Features() []secretstores.Feature {
	return []secretstores.Feature{}
}

// TestIsSecretAllowedWithReason tests the enhanced isSecretAllowed method
// to verify it correctly uses IsSecretAllowedWithReason and provides
// detailed logging.
func TestIsSecretAllowedWithReason(t *testing.T) {
	testCases := []struct {
		testName       string
		storeName      string
		key            string
		scope          config.SecretsScope
		expectedResult bool
		expectedReason string // This should match the reason in IsSecretAllowedWithReason
	}{
		{
			testName:  "Key allowed by default access",
			storeName: "store1",
			key:       "allowed-key",
			scope: config.SecretsScope{
				StoreName:     "store1",
				DefaultAccess: config.AllowAccess,
			},
			expectedResult: true,
			expectedReason: "DefaultAccess is set to 'allow' and key is not in DeniedSecrets",
		},
		{
			testName:  "Key denied by default access",
			storeName: "store2",
			key:       "random-key",
			scope: config.SecretsScope{
				StoreName:     "store2",
				DefaultAccess: config.DenyAccess,
			},
			expectedResult: false,
			expectedReason: "DefaultAccess is set to 'deny' and key is not in AllowedSecrets",
		},
		{
			testName:  "Key in allowed list",
			storeName: "store3",
			key:       "specific-key",
			scope: config.SecretsScope{
				StoreName:      "store3",
				DefaultAccess:  config.DenyAccess,
				AllowedSecrets: []string{"specific-key"},
			},
			expectedResult: true,
			expectedReason: "Key is in AllowedSecrets list",
		},
		{
			testName:  "Key not in allowed list",
			storeName: "store4",
			key:       "random-key",
			scope: config.SecretsScope{
				StoreName:      "store4",
				DefaultAccess:  config.AllowAccess,
				AllowedSecrets: []string{"specific-key"},
			},
			expectedResult: false,
			expectedReason: "Key is not in AllowedSecrets list and AllowedSecrets is configured",
		},
		{
			testName:  "Key in denied list",
			storeName: "store5",
			key:       "denied-key",
			scope: config.SecretsScope{
				StoreName:     "store5",
				DefaultAccess: config.AllowAccess,
				DeniedSecrets: []string{"denied-key"},
			},
			expectedResult: false,
			expectedReason: "Key is in DeniedSecrets list",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.testName, func(t *testing.T) {
			// Create a buffer to capture logs
			logBuffer := &bytes.Buffer{}
			testLogger := logger.NewLogger("test-secrets-logger")
			testLogger.SetOutput(io.MultiWriter(logBuffer, io.Discard)) // Send logs to buffer and nowhere
			testLogger.SetOutputLevel(logger.DebugLevel)

			// Create the component store and add the configuration
			compStore := compstore.New()
			compStore.AddSecretsConfiguration(tc.storeName, tc.scope)

			// Create the API with our test logger
			fakeAPI := &Universal{
				logger:    testLogger,
				compStore: compStore,
			}

			// Call the method
			result := fakeAPI.isSecretAllowed(tc.storeName, tc.key)

			// Verify the result
			assert.Equal(t, tc.expectedResult, result, "isSecretAllowed returned unexpected result")

			// For denied access, check that the logs contain the expected reason
			if !tc.expectedResult {
				// Check that the log contains the expected strings instead of parsing as JSON
				logContent := logBuffer.String()
				assert.Contains(t, logContent, "Secret access denied")
				assert.Contains(t, logContent, tc.key)
				assert.Contains(t, logContent, tc.storeName)
				assert.Contains(t, logContent, tc.expectedReason)
			}
		})
	}

	// Test case with no scoping configuration
	t.Run("No secret configuration returns true", func(t *testing.T) {
		// Create a buffer to capture logs
		logBuffer := &bytes.Buffer{}
		testLogger := logger.NewLogger("test-secrets-logger")
		testLogger.SetOutput(io.MultiWriter(logBuffer, io.Discard)) // Send logs to buffer and nowhere
		testLogger.SetOutputLevel(logger.DebugLevel)

		// Create the API with our test logger
		fakeAPI := &Universal{
			logger:    testLogger,
			compStore: compstore.New(), // Empty component store with no configurations
		}

		// Call the method
		result := fakeAPI.isSecretAllowed("non-existent-store", "some-key")

		// Verify the result
		assert.True(t, result, "isSecretAllowed should return true for non-configured store")

		// Verify the debug log
		assert.Contains(t, logBuffer.String(), "No secret scoping configuration found for store")
	})
}

func TestSecretStoreNotConfigured(t *testing.T) {
	// Setup Dapr API
	fakeAPI := &Universal{
		logger:    testLogger,
		compStore: compstore.New(),
	}

	// act
	t.Run("GetSecret", func(t *testing.T) {
		_, err := fakeAPI.GetSecret(t.Context(), &runtimev1pb.GetSecretRequest{})
		require.Error(t, err)
		require.ErrorIs(t, err, messages.ErrSecretStoreNotConfigured)
	})

	t.Run("GetBulkSecret", func(t *testing.T) {
		_, err := fakeAPI.GetBulkSecret(t.Context(), &runtimev1pb.GetBulkSecretRequest{})
		require.Error(t, err)
		require.ErrorIs(t, err, messages.ErrSecretStoreNotConfigured)
	})
}

func TestGetSecret(t *testing.T) {
	fakeStore := daprt.FakeSecretStore{}
	fakeStores := map[string]secretstores.SecretStore{
		"store1": fakeStore,
		"store2": fakeStore,
		"store3": fakeStore,
		"store4": fakeStore,
	}
	secretsConfiguration := map[string]config.SecretsScope{
		"store1": {
			DefaultAccess: config.AllowAccess,
			DeniedSecrets: []string{"not-allowed"},
		},
		"store2": {
			DefaultAccess:  config.DenyAccess,
			AllowedSecrets: []string{"good-key"},
		},
		"store3": {
			DefaultAccess:  config.AllowAccess,
			AllowedSecrets: []string{"error-key", "good-key"},
		},
	}
	expectedResponse := "life is good"
	storeName := "store1"
	deniedStoreName := "store2"
	restrictedStore := "store3"
	unrestrictedStore := "store4"     // No configuration defined for the store
	nonExistingStore := "nonexistent" // Non-existing store

	testCases := []struct {
		testName         string
		storeName        string
		key              string
		errorExcepted    bool
		expectedResponse string
		expectedError    codes.Code
	}{
		{
			testName:         "Good Key from unrestricted store",
			storeName:        unrestrictedStore,
			key:              "good-key",
			errorExcepted:    false,
			expectedResponse: expectedResponse,
		},
		{
			testName:         "Good Key default access",
			storeName:        storeName,
			key:              "good-key",
			errorExcepted:    false,
			expectedResponse: expectedResponse,
		},
		{
			testName:         "Good Key restricted store access",
			storeName:        restrictedStore,
			key:              "good-key",
			errorExcepted:    false,
			expectedResponse: expectedResponse,
		},
		{
			testName:         "Error Key restricted store access",
			storeName:        restrictedStore,
			key:              "error-key",
			errorExcepted:    true,
			expectedResponse: "",
			expectedError:    codes.Internal,
		},
		{
			testName:         "Random Key restricted store access",
			storeName:        restrictedStore,
			key:              "random",
			errorExcepted:    true,
			expectedResponse: "",
			expectedError:    codes.PermissionDenied,
		},
		{
			testName:         "Random Key accessing a store denied access by default",
			storeName:        deniedStoreName,
			key:              "random",
			errorExcepted:    true,
			expectedResponse: "",
			expectedError:    codes.PermissionDenied,
		},
		{
			testName:         "Random Key accessing a store denied access by default",
			storeName:        deniedStoreName,
			key:              "random",
			errorExcepted:    true,
			expectedResponse: "",
			expectedError:    codes.PermissionDenied,
		},
		{
			testName:         "Store doesn't exist",
			storeName:        nonExistingStore,
			key:              "key",
			errorExcepted:    true,
			expectedResponse: "",
			expectedError:    codes.InvalidArgument,
		},
	}

	compStore := compstore.New()
	for name, store := range fakeStores {
		compStore.AddSecretStore(name, store)
	}
	for name, conf := range secretsConfiguration {
		compStore.AddSecretsConfiguration(name, conf)
	}

	// Setup Dapr API
	fakeAPI := &Universal{
		logger:     testLogger,
		resiliency: resiliency.New(nil),
		compStore:  compStore,
	}

	// act
	for _, tt := range testCases {
		t.Run(tt.testName, func(t *testing.T) {
			req := &runtimev1pb.GetSecretRequest{
				StoreName: tt.storeName,
				Key:       tt.key,
			}
			resp, err := fakeAPI.GetSecret(t.Context(), req)

			if !tt.errorExcepted {
				require.NoError(t, err, "Expected no error")
				assert.Equal(t, tt.expectedResponse, resp.GetData()[tt.key], "Expected responses to be same")
			} else {
				require.Error(t, err, "Expected error")
				assert.Equal(t, tt.expectedError, status.Code(err))
			}
		})
	}
}

func TestGetBulkSecret(t *testing.T) {
	fakeStore := daprt.FakeSecretStore{}
	fakeStores := map[string]secretstores.SecretStore{
		"store1": fakeStore,
	}
	secretsConfiguration := map[string]config.SecretsScope{
		"store1": {
			DefaultAccess: config.AllowAccess,
			DeniedSecrets: []string{"not-allowed"},
		},
	}
	expectedResponse := "life is good"

	testCases := []struct {
		testName         string
		storeName        string
		key              string
		errorExcepted    bool
		expectedResponse string
		expectedError    codes.Code
	}{
		{
			testName:         "Good Key from unrestricted store",
			storeName:        "store1",
			key:              "good-key",
			errorExcepted:    false,
			expectedResponse: expectedResponse,
		},
	}

	compStore := compstore.New()
	for name, store := range fakeStores {
		compStore.AddSecretStore(name, store)
	}
	for name, conf := range secretsConfiguration {
		compStore.AddSecretsConfiguration(name, conf)
	}

	// Setup Dapr API
	fakeAPI := &Universal{
		logger:     testLogger,
		resiliency: resiliency.New(nil),
		compStore:  compStore,
	}

	// act
	for _, tt := range testCases {
		t.Run(tt.testName, func(t *testing.T) {
			req := &runtimev1pb.GetBulkSecretRequest{
				StoreName: tt.storeName,
			}
			resp, err := fakeAPI.GetBulkSecret(t.Context(), req)

			if !tt.errorExcepted {
				require.NoError(t, err, "Expected no error")
				assert.Equal(t, tt.expectedResponse, resp.GetData()[tt.key].GetSecrets()[tt.key], "Expected responses to be same")
			} else {
				require.Error(t, err, "Expected error")
				assert.Equal(t, tt.expectedError, status.Code(err))
			}
		})
	}
}

func TestSecretAPIWithResiliency(t *testing.T) {
	failingStore := daprt.FailingSecretStore{
		Failure: daprt.NewFailure(
			map[string]int{"key": 1, "bulk": 1},
			map[string]time.Duration{"timeout": time.Second * 30, "bulkTimeout": time.Second * 30},
			map[string]int{},
		),
	}

	compStore := compstore.New()
	compStore.AddSecretStore("failSecret", failingStore)

	// Setup Dapr API
	fakeAPI := &Universal{
		logger:     testLogger,
		resiliency: resiliency.FromConfigurations(testLogger, testResiliency),
		compStore:  compStore,
	}

	// act
	t.Run("Get secret - retries on initial failure with resiliency", func(t *testing.T) {
		_, err := fakeAPI.GetSecret(t.Context(), &runtimev1pb.GetSecretRequest{
			StoreName: "failSecret",
			Key:       "key",
		})

		require.NoError(t, err)
		assert.Equal(t, 2, failingStore.Failure.CallCount("key"))
	})

	t.Run("Get secret - timeout before request ends", func(t *testing.T) {
		// Store sleeps for 30 seconds, let's make sure our timeout takes less time than that.
		start := time.Now()
		_, err := fakeAPI.GetSecret(t.Context(), &runtimev1pb.GetSecretRequest{
			StoreName: "failSecret",
			Key:       "timeout",
		})
		end := time.Now()

		require.Error(t, err)
		assert.Equal(t, 2, failingStore.Failure.CallCount("timeout"))
		assert.Less(t, end.Sub(start), time.Second*30)
	})

	t.Run("Get bulk secret - retries on initial failure with resiliency", func(t *testing.T) {
		_, err := fakeAPI.GetBulkSecret(t.Context(), &runtimev1pb.GetBulkSecretRequest{
			StoreName: "failSecret",
			Metadata:  map[string]string{"key": "bulk"},
		})

		require.NoError(t, err)
		assert.Equal(t, 2, failingStore.Failure.CallCount("bulk"))
	})

	t.Run("Get bulk secret - timeout before request ends", func(t *testing.T) {
		start := time.Now()
		_, err := fakeAPI.GetBulkSecret(t.Context(), &runtimev1pb.GetBulkSecretRequest{
			StoreName: "failSecret",
			Metadata:  map[string]string{"key": "bulkTimeout"},
		})
		end := time.Now()

		require.Error(t, err)
		assert.Equal(t, 2, failingStore.Failure.CallCount("bulkTimeout"))
		assert.Less(t, end.Sub(start), time.Second*30)
	})
}

func TestGetSecretEnhancedLogging(t *testing.T) {
	// Create test components
	fakeStore := daprt.FakeSecretStore{}

	storeName := "test-store"
	secretKey := "denied-key"

	// Create a buffer to capture logs
	logBuffer := &bytes.Buffer{}
	testLogger := logger.NewLogger("test-secrets-logger")
	testLogger.SetOutput(io.MultiWriter(logBuffer, io.Discard)) // Send logs to buffer and nowhere
	testLogger.SetOutputLevel(logger.InfoLevel)

	// Setup component store with a secret store and a configuration that will deny access
	compStore := compstore.New()
	compStore.AddSecretStore(storeName, fakeStore)
	compStore.AddSecretsConfiguration(storeName, config.SecretsScope{
		StoreName:     storeName,
		DefaultAccess: config.DenyAccess,
	})

	// Create the API with our test logger
	fakeAPI := &Universal{
		logger:     testLogger,
		compStore:  compStore,
		resiliency: resiliency.New(nil),
	}

	// Execute the GetSecret method with parameters that will trigger a permission denial
	req := &runtimev1pb.GetSecretRequest{
		StoreName: storeName,
		Key:       secretKey,
	}

	// This should be denied and generate enhanced error logs
	_, err := fakeAPI.GetSecret(t.Context(), req)

	// Verify the error is as expected
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))

	// Check that the logs contain detailed information - without parsing as JSON
	logContent := logBuffer.String()
	assert.Contains(t, logContent, "Secret access denied")
	assert.Contains(t, logContent, secretKey)
	assert.Contains(t, logContent, storeName)
	assert.Contains(t, logContent, "DefaultAccess is set to 'deny'")
}

func TestGetBulkSecretEnhancedLogging(t *testing.T) {
	// Create a custom secret store that returns multiple secrets including one that will be denied
	mockBulkStore := CustomSecretStore{
		bulkSecrets: map[string]map[string]string{
			"allowed-key": {"allowed-key": "allowed value"},
			"denied-key":  {"denied-key": "denied value"},
		},
	}

	storeName := "test-store"
	deniedKey := "denied-key"

	// Create a buffer to capture logs
	logBuffer := &bytes.Buffer{}
	testLogger := logger.NewLogger("test-secrets-logger")
	testLogger.SetOutput(io.MultiWriter(logBuffer, io.Discard))
	testLogger.SetOutputLevel(logger.InfoLevel)

	// Setup component store with a secret store and a configuration that will deny specific secrets
	compStore := compstore.New()
	compStore.AddSecretStore(storeName, mockBulkStore)
	compStore.AddSecretsConfiguration(storeName, config.SecretsScope{
		StoreName:     storeName,
		DefaultAccess: config.AllowAccess,
		DeniedSecrets: []string{deniedKey},
	})

	// Create the API with our test logger
	fakeAPI := &Universal{
		logger:     testLogger,
		compStore:  compStore,
		resiliency: resiliency.New(nil),
	}

	// Execute the GetBulkSecret method
	req := &runtimev1pb.GetBulkSecretRequest{
		StoreName: storeName,
	}

	// This should filter out the denied secrets and log information about them
	resp, err := fakeAPI.GetBulkSecret(t.Context(), req)

	// Verify there was no error but the denied secret was filtered
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotNil(t, resp.Data)

	// The denied key should not be in the response
	_, exists := resp.Data[deniedKey]
	assert.False(t, exists, "Denied key should be filtered out of the response")

	// The allowed key should be in the response
	_, exists = resp.Data["allowed-key"]
	assert.True(t, exists, "Allowed key should be in the response")

	// Check that the logs contain detailed information about denied secrets
	logString := logBuffer.String()

	// Look for the enhanced denied secrets log
	assert.Contains(t, logString, "Some secrets were denied access")
	assert.Contains(t, logString, deniedKey)
	assert.Contains(t, logString, "Key is in DeniedSecrets list") // This is the reason
}

// TestCustomSecretStore is a simple test of our CustomSecretStore implementation
func TestCustomSecretStore(t *testing.T) {
	mockStore := CustomSecretStore{
		bulkSecrets: map[string]map[string]string{
			"key1": {"key1": "value1"},
			"key2": {"key2": "value2"},
		},
	}

	// Test GetSecret
	resp, err := mockStore.GetSecret(t.Context(), secretstores.GetSecretRequest{Name: "good-key"})
	require.NoError(t, err)
	assert.Equal(t, "life is good", resp.Data["good-key"])

	// Test BulkGetSecret
	bulkResp, err := mockStore.BulkGetSecret(t.Context(), secretstores.BulkGetSecretRequest{})
	require.NoError(t, err)
	assert.Equal(t, 2, len(bulkResp.Data))
	assert.Equal(t, "value1", bulkResp.Data["key1"]["key1"])
	assert.Equal(t, "value2", bulkResp.Data["key2"]["key2"])
}
