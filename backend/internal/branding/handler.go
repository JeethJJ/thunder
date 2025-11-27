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

package branding

import (
	"net/http"
	"net/url"
	"strconv"

	serverconst "github.com/asgardeo/thunder/internal/system/constants"
	"github.com/asgardeo/thunder/internal/system/error/apierror"
	"github.com/asgardeo/thunder/internal/system/error/serviceerror"
	"github.com/asgardeo/thunder/internal/system/log"
	sysutils "github.com/asgardeo/thunder/internal/system/utils"
)

const handlerLoggerComponentName = "BrandingHandler"

// brandingHandler is the handler for branding management operations.
type brandingHandler struct {
	brandingService BrandingServiceInterface
	logger          *log.Logger
}

// newBrandingHandler creates a new instance of brandingHandler
func newBrandingHandler(brandingService BrandingServiceInterface) *brandingHandler {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, handlerLoggerComponentName))
	return &brandingHandler{
		brandingService: brandingService,
		logger:          logger,
	}
}

// HandleBrandingListRequest handles the list branding configurations request.
func (bh *brandingHandler) HandleBrandingListRequest(w http.ResponseWriter, r *http.Request) {
	limit, offset, svcErr := parsePaginationParams(r.URL.Query())
	if svcErr != nil {
		handleError(w, bh.logger, svcErr)
		return
	}

	brandingList, svcErr := bh.brandingService.GetBrandingList(limit, offset)
	if svcErr != nil {
		handleError(w, bh.logger, svcErr)
		return
	}

	brandings := make([]BrandingListItem, 0, len(brandingList.Brandings))
	for _, branding := range brandingList.Brandings {
		brandings = append(brandings, BrandingListItem{
			ID:          branding.ID,
			DisplayName: branding.DisplayName,
		})
	}

	brandingListResponse := &BrandingListResponse{
		TotalResults: brandingList.TotalResults,
		StartIndex:   brandingList.StartIndex,
		Count:        brandingList.Count,
		Brandings:    brandings,
		Links:        toHTTPLinks(brandingList.Links),
	}

	sysutils.WriteSuccessResponse(w, http.StatusOK, brandingListResponse, bh.logger)

	bh.logger.Debug("Successfully listed branding configurations with pagination",
		log.Int("limit", limit), log.Int("offset", offset),
		log.Int("totalResults", brandingListResponse.TotalResults),
		log.Int("count", brandingListResponse.Count))
}

// HandleBrandingPostRequest handles the create branding configuration request.
func (bh *brandingHandler) HandleBrandingPostRequest(w http.ResponseWriter, r *http.Request) {
	createRequest, err := sysutils.DecodeJSONBody[CreateBrandingRequest](r)
	if err != nil {
		handleError(w, bh.logger, &ErrorInvalidRequestFormat)
		return
	}

	createdBranding, svcErr := bh.brandingService.CreateBranding(*createRequest)
	if svcErr != nil {
		handleError(w, bh.logger, svcErr)
		return
	}

	brandingResponse := BrandingResponse{
		ID:          createdBranding.ID,
		DisplayName: createdBranding.DisplayName,
		Preferences: createdBranding.Preferences,
	}

	sysutils.WriteSuccessResponse(w, http.StatusCreated, brandingResponse, bh.logger)

	bh.logger.Debug("Successfully created branding configuration", log.String("id", createdBranding.ID))
}

// HandleBrandingGetRequest handles the get branding configuration request.
func (bh *brandingHandler) HandleBrandingGetRequest(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	branding, svcErr := bh.brandingService.GetBranding(id)
	if svcErr != nil {
		handleError(w, bh.logger, svcErr)
		return
	}

	brandingResponse := BrandingResponse{
		ID:          branding.ID,
		DisplayName: branding.DisplayName,
		Preferences: branding.Preferences,
	}

	sysutils.WriteSuccessResponse(w, http.StatusOK, brandingResponse, bh.logger)

	bh.logger.Debug("Successfully retrieved branding configuration", log.String("id", id))
}

// HandleBrandingPutRequest handles the update branding configuration request.
func (bh *brandingHandler) HandleBrandingPutRequest(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	updateRequest, err := sysutils.DecodeJSONBody[UpdateBrandingRequest](r)
	if err != nil {
		handleError(w, bh.logger, &ErrorInvalidRequestFormat)
		return
	}

	updatedBranding, svcErr := bh.brandingService.UpdateBranding(id, *updateRequest)
	if svcErr != nil {
		handleError(w, bh.logger, svcErr)
		return
	}

	brandingResponse := BrandingResponse{
		ID:          updatedBranding.ID,
		DisplayName: updatedBranding.DisplayName,
		Preferences: updatedBranding.Preferences,
	}

	sysutils.WriteSuccessResponse(w, http.StatusOK, brandingResponse, bh.logger)

	bh.logger.Debug("Successfully updated branding configuration", log.String("id", id))
}

// HandleBrandingDeleteRequest handles the delete branding configuration request.
func (bh *brandingHandler) HandleBrandingDeleteRequest(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	svcErr := bh.brandingService.DeleteBranding(id)
	if svcErr != nil {
		handleError(w, bh.logger, svcErr)
		return
	}

	w.WriteHeader(http.StatusNoContent)
	bh.logger.Debug("Successfully deleted branding configuration", log.String("id", id))
}

// parsePaginationParams parses limit and offset query parameters from the request.
func parsePaginationParams(query url.Values) (int, int, *serviceerror.ServiceError) {
	limit := 0
	offset := 0

	if limitStr := query.Get("limit"); limitStr != "" {
		if parsedLimit, err := strconv.Atoi(limitStr); err != nil {
			return 0, 0, &ErrorInvalidLimit
		} else {
			limit = parsedLimit
		}
	}

	if offsetStr := query.Get("offset"); offsetStr != "" {
		if parsedOffset, err := strconv.Atoi(offsetStr); err != nil {
			return 0, 0, &ErrorInvalidOffset
		} else {
			offset = parsedOffset
		}
	}

	if limit == 0 {
		limit = serverconst.DefaultPageSize
	}

	return limit, offset, nil
}

// toHTTPLinks converts service layer Links to HTTP LinkResponses.
func toHTTPLinks(links []Link) []LinkResponse {
	httpLinks := make([]LinkResponse, len(links))
	for i, link := range links {
		httpLinks[i] = LinkResponse(link)
	}
	return httpLinks
}

// handleError handles service errors and returns appropriate HTTP responses.
func handleError(w http.ResponseWriter, logger *log.Logger,
	svcErr *serviceerror.ServiceError) {
	statusCode := http.StatusInternalServerError
	if svcErr.Type == serviceerror.ClientErrorType {
		switch svcErr.Code {
		case ErrorBrandingNotFound.Code:
			statusCode = http.StatusNotFound
		case ErrorCannotDeleteBranding.Code:
			statusCode = http.StatusConflict
		case ErrorInvalidRequestFormat.Code, ErrorMissingBrandingID.Code,
			ErrorInvalidLimit.Code, ErrorInvalidOffset.Code,
			ErrorMissingPreferences.Code, ErrorInvalidPreferences.Code,
			ErrorMissingDisplayName.Code:
			statusCode = http.StatusBadRequest
		default:
			statusCode = http.StatusBadRequest
		}
	}

	errResp := apierror.ErrorResponse{
		Code:        svcErr.Code,
		Message:     svcErr.Error,
		Description: svcErr.ErrorDescription,
	}
	sysutils.WriteErrorResponse(w, statusCode, errResp, logger)
}
