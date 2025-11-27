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

package authn

import (
	"net/http"

	"github.com/asgardeo/thunder/internal/authn/common"
	"github.com/asgardeo/thunder/internal/authn/credentials"
	"github.com/asgardeo/thunder/internal/authn/otp"
	"github.com/asgardeo/thunder/internal/idp"
	notifcommon "github.com/asgardeo/thunder/internal/notification/common"
	"github.com/asgardeo/thunder/internal/system/error/apierror"
	"github.com/asgardeo/thunder/internal/system/error/serviceerror"
	"github.com/asgardeo/thunder/internal/system/log"
	sysutils "github.com/asgardeo/thunder/internal/system/utils"
)

// authenticationHandler defines the handler for managing authentication API requests.
type authenticationHandler struct {
	authService AuthenticationServiceInterface
}

// newAuthenticationHandler creates a new instance of AuthenticationHandler.
func newAuthenticationHandler(authnService AuthenticationServiceInterface) *authenticationHandler {
	return &authenticationHandler{
		authService: authnService,
	}
}

// HandleCredentialsAuthRequest handles the credentials authentication request.
func (ah *authenticationHandler) HandleCredentialsAuthRequest(w http.ResponseWriter, r *http.Request) {
	authRequestPtr, err := sysutils.DecodeJSONBody[map[string]interface{}](r)
	if err != nil {
		ah.writeErrorResponse(w, http.StatusBadRequest, common.APIErrorInvalidRequestFormat)
		return
	}
	authRequest := *authRequestPtr

	// Check for skip_assertion field
	skipAssertion, ok := authRequest["skip_assertion"].(bool)
	if !ok {
		skipAssertion = false
	}
	delete(authRequest, "skip_assertion")

	// Check for assertion field
	assertion, ok := authRequest["assertion"].(string)
	if ok {
		delete(authRequest, "assertion")
	}

	authResponse, svcErr := ah.authService.AuthenticateWithCredentials(authRequest, skipAssertion, assertion)
	if svcErr != nil {
		ah.handleServiceError(w, svcErr)
		return
	}

	responseDTO := AuthenticationResponseDTO(*authResponse)
	ah.writeSuccessResponse(w, responseDTO)
}

// HandleSendSMSOTPRequest handles the send SMS OTP authentication request.
func (ah *authenticationHandler) HandleSendSMSOTPRequest(w http.ResponseWriter, r *http.Request) {
	otpRequest, err := sysutils.DecodeJSONBody[SendOTPAuthRequestDTO](r)
	if err != nil {
		ah.writeErrorResponse(w, http.StatusBadRequest, common.APIErrorInvalidRequestFormat)
		return
	}

	sessionToken, svcErr := ah.authService.SendOTP(otpRequest.SenderID, notifcommon.ChannelTypeSMS,
		otpRequest.Recipient)
	if svcErr != nil {
		ah.handleServiceError(w, svcErr)
		return
	}

	response := SendOTPAuthResponseDTO{
		Status:       "SUCCESS",
		SessionToken: sessionToken,
	}
	ah.writeSuccessResponse(w, response)
}

// HandleVerifySMSOTPRequest handles the verify SMS OTP authentication request.
func (ah *authenticationHandler) HandleVerifySMSOTPRequest(w http.ResponseWriter, r *http.Request) {
	otpRequest, err := sysutils.DecodeJSONBody[VerifyOTPAuthRequestDTO](r)
	if err != nil {
		ah.writeErrorResponse(w, http.StatusBadRequest, common.APIErrorInvalidRequestFormat)
		return
	}

	authResponse, svcErr := ah.authService.VerifyOTP(otpRequest.SessionToken, otpRequest.SkipAssertion,
		otpRequest.Assertion, otpRequest.OTP)
	if svcErr != nil {
		ah.handleServiceError(w, svcErr)
		return
	}

	responseDTO := AuthenticationResponseDTO(*authResponse)
	ah.writeSuccessResponse(w, responseDTO)
}

// HandleGoogleAuthStartRequest handles the Google OAuth start authentication request.
func (ah *authenticationHandler) HandleGoogleAuthStartRequest(w http.ResponseWriter, r *http.Request) {
	authRequest, err := sysutils.DecodeJSONBody[IDPAuthInitRequestDTO](r)
	if err != nil {
		ah.writeErrorResponse(w, http.StatusBadRequest, common.APIErrorInvalidRequestFormat)
		return
	}

	authResponse, svcErr := ah.authService.StartIDPAuthentication(idp.IDPTypeGoogle, authRequest.IDPID)
	if svcErr != nil {
		ah.handleServiceError(w, svcErr)
		return
	}

	response := IDPAuthInitResponseDTO(*authResponse)
	ah.writeSuccessResponse(w, response)
}

// HandleGoogleAuthFinishRequest handles the Google OAuth finish authentication request.
func (ah *authenticationHandler) HandleGoogleAuthFinishRequest(w http.ResponseWriter, r *http.Request) {
	authRequest, err := sysutils.DecodeJSONBody[IDPAuthFinishRequestDTO](r)
	if err != nil {
		ah.writeErrorResponse(w, http.StatusBadRequest, common.APIErrorInvalidRequestFormat)
		return
	}

	authResponse, svcErr := ah.authService.FinishIDPAuthentication(idp.IDPTypeGoogle, authRequest.SessionToken,
		authRequest.SkipAssertion, authRequest.Assertion, authRequest.Code)
	if svcErr != nil {
		ah.handleServiceError(w, svcErr)
		return
	}

	responseDTO := AuthenticationResponseDTO(*authResponse)
	ah.writeSuccessResponse(w, responseDTO)
}

// HandleGithubAuthStartRequest handles the GitHub OAuth start authentication request.
func (ah *authenticationHandler) HandleGithubAuthStartRequest(w http.ResponseWriter, r *http.Request) {
	authRequest, err := sysutils.DecodeJSONBody[IDPAuthInitRequestDTO](r)
	if err != nil {
		ah.writeErrorResponse(w, http.StatusBadRequest, common.APIErrorInvalidRequestFormat)
		return
	}

	authResponse, svcErr := ah.authService.StartIDPAuthentication(idp.IDPTypeGitHub, authRequest.IDPID)
	if svcErr != nil {
		ah.handleServiceError(w, svcErr)
		return
	}

	responseDTO := IDPAuthInitResponseDTO(*authResponse)
	ah.writeSuccessResponse(w, responseDTO)
}

// HandleGithubAuthFinishRequest handles the GitHub OAuth finish authentication request.
func (ah *authenticationHandler) HandleGithubAuthFinishRequest(w http.ResponseWriter, r *http.Request) {
	authRequest, err := sysutils.DecodeJSONBody[IDPAuthFinishRequestDTO](r)
	if err != nil {
		ah.writeErrorResponse(w, http.StatusBadRequest, common.APIErrorInvalidRequestFormat)
		return
	}

	authResponse, svcErr := ah.authService.FinishIDPAuthentication(idp.IDPTypeGitHub, authRequest.SessionToken,
		authRequest.SkipAssertion, authRequest.Assertion, authRequest.Code)
	if svcErr != nil {
		ah.handleServiceError(w, svcErr)
		return
	}

	responseDTO := AuthenticationResponseDTO(*authResponse)
	ah.writeSuccessResponse(w, responseDTO)
}

// HandleStandardOAuthStartRequest handles the standard OAuth start authentication request.
func (ah *authenticationHandler) HandleStandardOAuthStartRequest(w http.ResponseWriter, r *http.Request) {
	authRequest, err := sysutils.DecodeJSONBody[IDPAuthInitRequestDTO](r)
	if err != nil {
		ah.writeErrorResponse(w, http.StatusBadRequest, common.APIErrorInvalidRequestFormat)
		return
	}

	authResponse, svcErr := ah.authService.StartIDPAuthentication(idp.IDPTypeOAuth, authRequest.IDPID)
	if svcErr != nil {
		ah.handleServiceError(w, svcErr)
		return
	}

	responseDTO := IDPAuthInitResponseDTO(*authResponse)
	ah.writeSuccessResponse(w, responseDTO)
}

// HandleStandardOAuthFinishRequest handles the standard OAuth finish authentication request.
func (ah *authenticationHandler) HandleStandardOAuthFinishRequest(w http.ResponseWriter, r *http.Request) {
	authRequest, err := sysutils.DecodeJSONBody[IDPAuthFinishRequestDTO](r)
	if err != nil {
		ah.writeErrorResponse(w, http.StatusBadRequest, common.APIErrorInvalidRequestFormat)
		return
	}

	authResponse, svcErr := ah.authService.FinishIDPAuthentication(idp.IDPTypeOAuth, authRequest.SessionToken,
		authRequest.SkipAssertion, authRequest.Assertion, authRequest.Code)
	if svcErr != nil {
		ah.handleServiceError(w, svcErr)
		return
	}

	responseDTO := AuthenticationResponseDTO(*authResponse)
	ah.writeSuccessResponse(w, responseDTO)
}

// handleServiceError converts service errors to appropriate HTTP responses.
func (ah *authenticationHandler) handleServiceError(w http.ResponseWriter, svcErr *serviceerror.ServiceError) {
	status := http.StatusInternalServerError
	if svcErr.Type == serviceerror.ClientErrorType {
		switch svcErr.Code {
		case credentials.ErrorInvalidCredentials.Code, otp.ErrorIncorrectOTP.Code:
			status = http.StatusUnauthorized
		case common.ErrorUserNotFound.Code:
			status = http.StatusNotFound
		default:
			status = http.StatusBadRequest
		}
	}

	errorResp := apierror.ErrorResponse{
		Code:        svcErr.Code,
		Message:     svcErr.Error,
		Description: svcErr.ErrorDescription,
	}
	ah.writeErrorResponse(w, status, errorResp)
}

// writeSuccessResponse writes a successful JSON response.
func (ah *authenticationHandler) writeSuccessResponse(w http.ResponseWriter, data interface{}) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "AuthenticationHandler"))
	sysutils.WriteSuccessResponse(w, http.StatusOK, data, logger)
}

// writeErrorResponse writes an error response.
func (ah *authenticationHandler) writeErrorResponse(w http.ResponseWriter,
	statusCode int, errorResp apierror.ErrorResponse) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "AuthenticationHandler"))
	sysutils.WriteErrorResponse(w, statusCode, errorResp, logger)
}
