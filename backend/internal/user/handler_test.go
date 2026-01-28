/*
 * Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package user

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/asgardeo/thunder/internal/system/error/apierror"
	"github.com/asgardeo/thunder/internal/system/error/serviceerror"
	"github.com/asgardeo/thunder/internal/system/security"
)

const (
	testUserID789 = "user-789"
)

func TestHandleSelfUserGetRequest_Success(t *testing.T) {
	userID := "user-123"
	authCtx := security.NewSecurityContextForTest(userID, "", "", "", nil)

	mockSvc := NewUserServiceInterfaceMock(t)
	expectedUser := &User{
		ID:         userID,
		Attributes: json.RawMessage(`{"username":"alice"}`),
	}
	mockSvc.On("GetUser", mock.Anything, userID).Return(expectedUser, nil)

	handler := newUserHandler(mockSvc)
	req := httptest.NewRequest(http.MethodGet, "/users/me", nil)
	req = req.WithContext(security.WithSecurityContextTest(req.Context(), authCtx))
	rr := httptest.NewRecorder()

	handler.HandleSelfUserGetRequest(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	require.Contains(t, rr.Header().Get("Content-Type"), "application/json")

	var respUser User
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&respUser))
	require.Equal(t, expectedUser.ID, respUser.ID)
	require.JSONEq(t, string(expectedUser.Attributes), string(respUser.Attributes))
}

func TestHandleSelfUserGetRequest_Unauthorized(t *testing.T) {
	mockSvc := NewUserServiceInterfaceMock(t)
	handler := newUserHandler(mockSvc)
	req := httptest.NewRequest(http.MethodGet, "/users/me", nil)
	rr := httptest.NewRecorder()

	handler.HandleSelfUserGetRequest(rr, req)

	require.Equal(t, http.StatusUnauthorized, rr.Code)

	var errResp apierror.ErrorResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	require.Equal(t, ErrorAuthenticationFailed.Code, errResp.Code)
}

func TestHandleSelfUserPutRequest_Success(t *testing.T) {
	userID := "user-456"
	authCtx := security.NewSecurityContextForTest(userID, "", "", "", nil)
	attributes := json.RawMessage(`{"email":"alice@example.com"}`)

	mockSvc := NewUserServiceInterfaceMock(t)
	updatedUser := &User{
		ID:         userID,
		Type:       "employee",
		Attributes: attributes,
	}
	mockSvc.On("UpdateUserAttributes", mock.Anything, userID, attributes).Return(updatedUser, nil)

	handler := newUserHandler(mockSvc)
	body := bytes.NewBufferString(`{"attributes":{"email":"alice@example.com"}}`)
	req := httptest.NewRequest(http.MethodPut, "/users/me", body)
	req = req.WithContext(security.WithSecurityContextTest(req.Context(), authCtx))
	rr := httptest.NewRecorder()

	handler.HandleSelfUserPutRequest(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)

	var respUser User
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&respUser))
	require.Equal(t, updatedUser.ID, respUser.ID)
	require.JSONEq(t, string(updatedUser.Attributes), string(respUser.Attributes))
}

func TestHandleSelfUserPutRequest_InvalidBody(t *testing.T) {
	userID := "user-456"
	authCtx := security.NewSecurityContextForTest(userID, "", "", "", nil)

	mockSvc := NewUserServiceInterfaceMock(t)
	handler := newUserHandler(mockSvc)

	req := httptest.NewRequest(http.MethodPut, "/users/me", bytes.NewBufferString(`{"attributes":`))
	req = req.WithContext(security.WithSecurityContextTest(req.Context(), authCtx))
	rr := httptest.NewRecorder()

	handler.HandleSelfUserPutRequest(rr, req)

	require.Equal(t, http.StatusBadRequest, rr.Code)

	var errResp apierror.ErrorResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	require.Equal(t, ErrorInvalidRequestFormat.Code, errResp.Code)
}

func TestHandleSelfUserCredentialUpdateRequest_Success(t *testing.T) {
	userID := testUserID789
	authCtx := security.NewSecurityContextForTest(userID, "", "", "", nil)

	mockSvc := NewUserServiceInterfaceMock(t)
	credentialsJSON := json.RawMessage(`{"password":[{"value":"Secret123!"}]}`)
	mockSvc.On("UpdateUserCredentials", mock.Anything, userID, credentialsJSON).Return(nil)

	handler := newUserHandler(mockSvc)
	req := httptest.NewRequest(http.MethodPost, "/users/me/update-credentials",
		bytes.NewBufferString(`{"attributes":{"password":[{"value":"Secret123!"}]}}`))
	req = req.WithContext(security.WithSecurityContextTest(req.Context(), authCtx))
	rr := httptest.NewRecorder()

	handler.HandleSelfUserCredentialUpdateRequest(rr, req)

	require.Equal(t, http.StatusNoContent, rr.Code)
	require.Equal(t, 0, rr.Body.Len())
}

func TestHandleSelfUserCredentialUpdateRequest_StringValue(t *testing.T) {
	userID := testUserID789
	authCtx := security.NewSecurityContextForTest(userID, "", "", "", nil)

	mockSvc := NewUserServiceInterfaceMock(t)
	credentialsJSON := json.RawMessage(`{"password":"plaintext-password"}`)
	mockSvc.On("UpdateUserCredentials", mock.Anything, userID, credentialsJSON).Return(nil)

	handler := newUserHandler(mockSvc)
	req := httptest.NewRequest(http.MethodPost, "/users/me/update-credentials",
		bytes.NewBufferString(`{"attributes":{"password":"plaintext-password"}}`))
	req = req.WithContext(security.WithSecurityContextTest(req.Context(), authCtx))
	rr := httptest.NewRecorder()

	handler.HandleSelfUserCredentialUpdateRequest(rr, req)

	require.Equal(t, http.StatusNoContent, rr.Code)
	require.Equal(t, 0, rr.Body.Len())
}

func TestHandleSelfUserCredentialUpdateRequest_MissingCredentials(t *testing.T) {
	userID := testUserID789
	authCtx := security.NewSecurityContextForTest(userID, "", "", "", nil)

	mockSvc := NewUserServiceInterfaceMock(t)
	handler := newUserHandler(mockSvc)

	req := httptest.NewRequest(http.MethodPost, "/users/me/update-credentials",
		bytes.NewBufferString(`{"attributes":{}}`))
	req = req.WithContext(security.WithSecurityContextTest(req.Context(), authCtx))
	rr := httptest.NewRecorder()

	handler.HandleSelfUserCredentialUpdateRequest(rr, req)

	require.Equal(t, http.StatusBadRequest, rr.Code)

	var errResp apierror.ErrorResponse
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
	require.Equal(t, ErrorMissingCredentials.Code, errResp.Code)
}

func TestHandleSelfUserCredentialUpdateRequest_ErrorCases(t *testing.T) {
	userID := testUserID789
	authCtx := security.NewSecurityContextForTest(userID, "", "", "", nil)

	testCases := []struct {
		name             string
		requestBody      string
		mockJSON         json.RawMessage
		mockError        *serviceerror.ServiceError
		expectedHTTPCode int
		expectedErrCode  string
	}{
		{
			name:             "Invalid JSON in attributes",
			requestBody:      `{"attributes":["invalid","array"]}`,
			mockJSON:         json.RawMessage(`["invalid","array"]`),
			mockError:        &ErrorInvalidRequestFormat,
			expectedHTTPCode: http.StatusBadRequest,
			expectedErrCode:  ErrorInvalidRequestFormat.Code,
		},
		{
			name:             "Invalid credential type",
			requestBody:      `{"attributes":{"unsupported_type":"some_value"}}`,
			mockJSON:         json.RawMessage(`{"unsupported_type":"some_value"}`),
			mockError:        &ErrorInvalidCredential,
			expectedHTTPCode: http.StatusBadRequest,
			expectedErrCode:  ErrorInvalidCredential.Code,
		},
		{
			name:             "Service error",
			requestBody:      `{"attributes":{"password":"test_password"}}`,
			mockJSON:         json.RawMessage(`{"password":"test_password"}`),
			mockError:        &ErrorInvalidCredential,
			expectedHTTPCode: http.StatusBadRequest,
			expectedErrCode:  ErrorInvalidCredential.Code,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockSvc := NewUserServiceInterfaceMock(t)
			mockSvc.On("UpdateUserCredentials", mock.Anything, userID, tc.mockJSON).Return(tc.mockError)

			handler := newUserHandler(mockSvc)
			req := httptest.NewRequest(http.MethodPost, "/users/me/update-credentials",
				bytes.NewBufferString(tc.requestBody))
			req = req.WithContext(security.WithSecurityContextTest(req.Context(), authCtx))
			rr := httptest.NewRecorder()

			handler.HandleSelfUserCredentialUpdateRequest(rr, req)

			require.Equal(t, tc.expectedHTTPCode, rr.Code)

			var errResp apierror.ErrorResponse
			require.NoError(t, json.NewDecoder(rr.Body).Decode(&errResp))
			require.Equal(t, tc.expectedErrCode, errResp.Code)
		})
	}
}

func TestHandleSelfUserCredentialUpdateRequest_MultipleCredentialTypes(t *testing.T) {
	userID := testUserID789
	authCtx := security.NewSecurityContextForTest(userID, "", "", "", nil)

	mockSvc := NewUserServiceInterfaceMock(t)
	// Test that multiple credential types are updated in a single atomic call
	credentialsJSON := json.RawMessage(`{"password":"new-password","pin":"1234"}`)
	mockSvc.On("UpdateUserCredentials", mock.Anything, userID, credentialsJSON).Return(nil)

	handler := newUserHandler(mockSvc)
	req := httptest.NewRequest(http.MethodPost, "/users/me/update-credentials",
		bytes.NewBufferString(`{"attributes":{"password":"new-password","pin":"1234"}}`))
	req = req.WithContext(security.WithSecurityContextTest(req.Context(), authCtx))
	rr := httptest.NewRecorder()

	handler.HandleSelfUserCredentialUpdateRequest(rr, req)

	require.Equal(t, http.StatusNoContent, rr.Code)
	require.Equal(t, 0, rr.Body.Len())
	// Verify that UpdateUserCredentials was called exactly once with all credentials
	mockSvc.AssertNumberOfCalls(t, "UpdateUserCredentials", 1)
}
