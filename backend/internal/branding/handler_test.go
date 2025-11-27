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
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/asgardeo/thunder/internal/system/error/serviceerror"
	"github.com/asgardeo/thunder/internal/system/log"
)

type BrandingHandlerTestSuite struct {
	suite.Suite
	mockService *BrandingServiceInterfaceMock
	handler     *brandingHandler
}

func TestBrandingHandlerTestSuite(t *testing.T) {
	suite.Run(t, new(BrandingHandlerTestSuite))
}

func (suite *BrandingHandlerTestSuite) SetupTest() {
	suite.mockService = NewBrandingServiceInterfaceMock(suite.T())
	suite.handler = newBrandingHandler(suite.mockService)
}

// HandleBrandingListRequest Tests
func (suite *BrandingHandlerTestSuite) TestHandleBrandingListRequest_Success() {
	expectedList := &BrandingList{
		TotalResults: 2,
		StartIndex:   1,
		Count:        2,
		Brandings: []Branding{
			{ID: "brand1", DisplayName: "Application 1 Branding"},
			{ID: "brand2", DisplayName: "Application 2 Branding"},
		},
		Links: []Link{},
	}

	suite.mockService.On("GetBrandingList", 10, 0).Return(expectedList, nil)

	req := httptest.NewRequest(http.MethodGet, "/branding?limit=10&offset=0", nil)
	w := httptest.NewRecorder()

	suite.handler.HandleBrandingListRequest(w, req)

	suite.Equal(http.StatusOK, w.Code)

	var response BrandingListResponse
	err := json.NewDecoder(w.Body).Decode(&response)
	suite.NoError(err)
	suite.Equal(2, response.TotalResults)
	suite.Equal(2, len(response.Brandings))
	suite.Equal("brand1", response.Brandings[0].ID)
	suite.Equal("Application 1 Branding", response.Brandings[0].DisplayName)
	suite.Equal("brand2", response.Brandings[1].ID)
	suite.Equal("Application 2 Branding", response.Brandings[1].DisplayName)
}

func (suite *BrandingHandlerTestSuite) TestHandleBrandingListRequest_DefaultPagination() {
	expectedList := &BrandingList{
		TotalResults: 1,
		StartIndex:   1,
		Count:        1,
		Brandings:    []Branding{{ID: "brand1", DisplayName: "Application 1 Branding"}},
		Links:        []Link{},
	}

	suite.mockService.On("GetBrandingList", 30, 0).Return(expectedList, nil)

	req := httptest.NewRequest(http.MethodGet, "/branding", nil)
	w := httptest.NewRecorder()

	suite.handler.HandleBrandingListRequest(w, req)

	suite.Equal(http.StatusOK, w.Code)
}

func (suite *BrandingHandlerTestSuite) TestHandleBrandingListRequest_InvalidLimit() {
	// When limit is invalid, parsePaginationParams returns error before calling service
	req := httptest.NewRequest(http.MethodGet, "/branding?limit=invalid", nil)
	w := httptest.NewRecorder()

	suite.handler.HandleBrandingListRequest(w, req)

	suite.Equal(http.StatusBadRequest, w.Code)
}

func (suite *BrandingHandlerTestSuite) TestHandleBrandingListRequest_InvalidOffset() {
	// When offset is invalid, parsePaginationParams returns error before calling service
	req := httptest.NewRequest(http.MethodGet, "/branding?offset=invalid", nil)
	w := httptest.NewRecorder()

	suite.handler.HandleBrandingListRequest(w, req)

	suite.Equal(http.StatusBadRequest, w.Code)
}

func (suite *BrandingHandlerTestSuite) TestHandleBrandingListRequest_ServiceError() {
	suite.mockService.On("GetBrandingList", 10, 0).Return(nil, &serviceerror.InternalServerError)

	req := httptest.NewRequest(http.MethodGet, "/branding?limit=10&offset=0", nil)
	w := httptest.NewRecorder()

	suite.handler.HandleBrandingListRequest(w, req)

	suite.Equal(http.StatusInternalServerError, w.Code)
}

// HandleBrandingPostRequest Tests
func (suite *BrandingHandlerTestSuite) TestHandleBrandingPostRequest_Success() {
	request := CreateBrandingRequest{
		DisplayName: "Application 1 Branding",
		Preferences: json.RawMessage(`{"theme":{"activeColorScheme":"dark"}}`),
	}

	expectedBranding := &Branding{
		ID:          "brand1",
		DisplayName: "Application 1 Branding",
		Preferences: json.RawMessage(`{"theme":{"activeColorScheme":"dark"}}`),
	}

	suite.mockService.On("CreateBranding", request).Return(expectedBranding, nil)

	body, _ := json.Marshal(request)
	req := httptest.NewRequest(http.MethodPost, "/branding", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	suite.handler.HandleBrandingPostRequest(w, req)

	suite.Equal(http.StatusCreated, w.Code)

	var response BrandingResponse
	err := json.NewDecoder(w.Body).Decode(&response)
	suite.NoError(err)
	suite.Equal("brand1", response.ID)
	suite.Equal("Application 1 Branding", response.DisplayName)
}

func (suite *BrandingHandlerTestSuite) TestHandleBrandingPostRequest_InvalidJSON() {
	req := httptest.NewRequest(http.MethodPost, "/branding", bytes.NewBufferString("invalid json"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	suite.handler.HandleBrandingPostRequest(w, req)

	suite.Equal(http.StatusBadRequest, w.Code)
}

func (suite *BrandingHandlerTestSuite) TestHandleBrandingPostRequest_MissingDisplayName() {
	request := CreateBrandingRequest{
		DisplayName: "",
		Preferences: json.RawMessage(`{}`),
	}

	suite.mockService.On("CreateBranding", request).Return(nil, &ErrorMissingDisplayName)

	body, _ := json.Marshal(request)
	req := httptest.NewRequest(http.MethodPost, "/branding", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	suite.handler.HandleBrandingPostRequest(w, req)

	suite.Equal(http.StatusBadRequest, w.Code)
}

func (suite *BrandingHandlerTestSuite) TestHandleBrandingPostRequest_ServiceError() {
	request := CreateBrandingRequest{
		DisplayName: "Application 1 Branding",
		Preferences: json.RawMessage(`{}`),
	}

	suite.mockService.On("CreateBranding", request).Return(nil, &ErrorInvalidPreferences)

	body, _ := json.Marshal(request)
	req := httptest.NewRequest(http.MethodPost, "/branding", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	suite.handler.HandleBrandingPostRequest(w, req)

	suite.Equal(http.StatusBadRequest, w.Code)
}

// HandleBrandingGetRequest Tests
func (suite *BrandingHandlerTestSuite) TestHandleBrandingGetRequest_Success() {
	expectedBranding := &Branding{
		ID:          "brand1",
		DisplayName: "Application 1 Branding",
		Preferences: json.RawMessage(`{"theme":"dark"}`),
	}

	suite.mockService.On("GetBranding", "brand1").Return(expectedBranding, nil)

	req := httptest.NewRequest(http.MethodGet, "/branding/brand1", nil)
	req.SetPathValue("id", "brand1")
	w := httptest.NewRecorder()

	suite.handler.HandleBrandingGetRequest(w, req)

	suite.Equal(http.StatusOK, w.Code)

	var response BrandingResponse
	err := json.NewDecoder(w.Body).Decode(&response)
	suite.NoError(err)
	suite.Equal("brand1", response.ID)
	suite.Equal("Application 1 Branding", response.DisplayName)
}

func (suite *BrandingHandlerTestSuite) TestHandleBrandingGetRequest_NotFound() {
	suite.mockService.On("GetBranding", "brand1").Return(nil, &ErrorBrandingNotFound)

	req := httptest.NewRequest(http.MethodGet, "/branding/brand1", nil)
	req.SetPathValue("id", "brand1")
	w := httptest.NewRecorder()

	suite.handler.HandleBrandingGetRequest(w, req)

	suite.Equal(http.StatusNotFound, w.Code)
}

func (suite *BrandingHandlerTestSuite) TestHandleBrandingGetRequest_ServiceError() {
	suite.mockService.On("GetBranding", "brand1").Return(nil, &serviceerror.InternalServerError)

	req := httptest.NewRequest(http.MethodGet, "/branding/brand1", nil)
	req.SetPathValue("id", "brand1")
	w := httptest.NewRecorder()

	suite.handler.HandleBrandingGetRequest(w, req)

	suite.Equal(http.StatusInternalServerError, w.Code)
}

// HandleBrandingPutRequest Tests
func (suite *BrandingHandlerTestSuite) TestHandleBrandingPutRequest_Success() {
	request := UpdateBrandingRequest{
		DisplayName: "Application 2 Branding",
		Preferences: json.RawMessage(`{"theme":{"activeColorScheme":"light"}}`),
	}

	expectedBranding := &Branding{
		ID:          "brand1",
		DisplayName: "Application 2 Branding",
		Preferences: json.RawMessage(`{"theme":{"activeColorScheme":"light"}}`),
	}

	suite.mockService.On("UpdateBranding", "brand1", request).Return(expectedBranding, nil)

	body, _ := json.Marshal(request)
	req := httptest.NewRequest(http.MethodPut, "/branding/brand1", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("id", "brand1")
	w := httptest.NewRecorder()

	suite.handler.HandleBrandingPutRequest(w, req)

	suite.Equal(http.StatusOK, w.Code)

	var response BrandingResponse
	err := json.NewDecoder(w.Body).Decode(&response)
	suite.NoError(err)
	suite.Equal("brand1", response.ID)
	suite.Equal("Application 2 Branding", response.DisplayName)
}

func (suite *BrandingHandlerTestSuite) TestHandleBrandingPutRequest_InvalidJSON() {
	req := httptest.NewRequest(http.MethodPut, "/branding/brand1", bytes.NewBufferString("invalid json"))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("id", "brand1")
	w := httptest.NewRecorder()

	suite.handler.HandleBrandingPutRequest(w, req)

	suite.Equal(http.StatusBadRequest, w.Code)
}

func (suite *BrandingHandlerTestSuite) TestHandleBrandingPutRequest_NotFound() {
	request := UpdateBrandingRequest{
		DisplayName: "Application 1 Branding",
		Preferences: json.RawMessage(`{}`),
	}

	suite.mockService.On("UpdateBranding", "brand1", request).Return(nil, &ErrorBrandingNotFound)

	body, _ := json.Marshal(request)
	req := httptest.NewRequest(http.MethodPut, "/branding/brand1", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("id", "brand1")
	w := httptest.NewRecorder()

	suite.handler.HandleBrandingPutRequest(w, req)

	suite.Equal(http.StatusNotFound, w.Code)
}

func (suite *BrandingHandlerTestSuite) TestHandleBrandingPutRequest_MissingDisplayName() {
	request := UpdateBrandingRequest{
		DisplayName: "",
		Preferences: json.RawMessage(`{}`),
	}

	suite.mockService.On("UpdateBranding", "brand1", request).Return(nil, &ErrorMissingDisplayName)

	body, _ := json.Marshal(request)
	req := httptest.NewRequest(http.MethodPut, "/branding/brand1", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("id", "brand1")
	w := httptest.NewRecorder()

	suite.handler.HandleBrandingPutRequest(w, req)

	suite.Equal(http.StatusBadRequest, w.Code)
}

func (suite *BrandingHandlerTestSuite) TestHandleBrandingPutRequest_ServiceError() {
	request := UpdateBrandingRequest{
		DisplayName: "Application 1 Branding",
		Preferences: json.RawMessage(`{}`),
	}

	suite.mockService.On("UpdateBranding", "brand1", request).Return(nil, &ErrorInvalidPreferences)

	body, _ := json.Marshal(request)
	req := httptest.NewRequest(http.MethodPut, "/branding/brand1", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("id", "brand1")
	w := httptest.NewRecorder()

	suite.handler.HandleBrandingPutRequest(w, req)

	suite.Equal(http.StatusBadRequest, w.Code)
}

// HandleBrandingDeleteRequest Tests
func (suite *BrandingHandlerTestSuite) TestHandleBrandingDeleteRequest_Success() {
	suite.mockService.On("DeleteBranding", "brand1").Return(nil)

	req := httptest.NewRequest(http.MethodDelete, "/branding/brand1", nil)
	req.SetPathValue("id", "brand1")
	w := httptest.NewRecorder()

	suite.handler.HandleBrandingDeleteRequest(w, req)

	suite.Equal(http.StatusNoContent, w.Code)
}

func (suite *BrandingHandlerTestSuite) TestHandleBrandingDeleteRequest_NotFound() {
	// According to YAML, delete returns 204 even when not found ("deleted or already deleted")
	suite.mockService.On("DeleteBranding", "brand1").Return(nil)

	req := httptest.NewRequest(http.MethodDelete, "/branding/brand1", nil)
	req.SetPathValue("id", "brand1")
	w := httptest.NewRecorder()

	suite.handler.HandleBrandingDeleteRequest(w, req)

	suite.Equal(http.StatusNoContent, w.Code)
}

func (suite *BrandingHandlerTestSuite) TestHandleBrandingDeleteRequest_CannotDelete() {
	suite.mockService.On("DeleteBranding", "brand1").Return(&ErrorCannotDeleteBranding)

	req := httptest.NewRequest(http.MethodDelete, "/branding/brand1", nil)
	req.SetPathValue("id", "brand1")
	w := httptest.NewRecorder()

	suite.handler.HandleBrandingDeleteRequest(w, req)

	suite.Equal(http.StatusConflict, w.Code)
}

func (suite *BrandingHandlerTestSuite) TestHandleBrandingDeleteRequest_ServiceError() {
	suite.mockService.On("DeleteBranding", "brand1").Return(&serviceerror.InternalServerError)

	req := httptest.NewRequest(http.MethodDelete, "/branding/brand1", nil)
	req.SetPathValue("id", "brand1")
	w := httptest.NewRecorder()

	suite.handler.HandleBrandingDeleteRequest(w, req)

	suite.Equal(http.StatusInternalServerError, w.Code)
}

// parsePaginationParams Tests
func (suite *BrandingHandlerTestSuite) TestParsePaginationParams_WithBothParams() {
	query := map[string][]string{
		"limit":  {"10"},
		"offset": {"5"},
	}
	limit, offset, err := parsePaginationParams(query)

	suite.Nil(err)
	suite.Equal(10, limit)
	suite.Equal(5, offset)
}

func (suite *BrandingHandlerTestSuite) TestParsePaginationParams_WithLimitOnly() {
	query := map[string][]string{
		"limit": {"10"},
	}
	limit, offset, err := parsePaginationParams(query)

	suite.Nil(err)
	suite.Equal(10, limit)
	suite.Equal(0, offset)
}

func (suite *BrandingHandlerTestSuite) TestParsePaginationParams_WithOffsetOnly() {
	query := map[string][]string{
		"offset": {"5"},
	}
	limit, offset, err := parsePaginationParams(query)

	suite.Nil(err)
	suite.Equal(30, limit) // Default limit
	suite.Equal(5, offset)
}

func (suite *BrandingHandlerTestSuite) TestParsePaginationParams_NoParams() {
	query := map[string][]string{}
	limit, offset, err := parsePaginationParams(query)

	suite.Nil(err)
	suite.Equal(30, limit) // Default limit
	suite.Equal(0, offset)
}

func (suite *BrandingHandlerTestSuite) TestParsePaginationParams_InvalidLimit() {
	query := map[string][]string{
		"limit": {"invalid"},
	}
	limit, offset, err := parsePaginationParams(query)

	suite.NotNil(err)
	suite.Equal(0, limit)
	suite.Equal(0, offset)
	suite.Equal(ErrorInvalidLimit.Code, err.Code)
}

func (suite *BrandingHandlerTestSuite) TestParsePaginationParams_InvalidOffset() {
	query := map[string][]string{
		"offset": {"invalid"},
	}
	limit, offset, err := parsePaginationParams(query)

	suite.NotNil(err)
	suite.Equal(0, limit)
	suite.Equal(0, offset)
	suite.Equal(ErrorInvalidOffset.Code, err.Code)
}

// toHTTPLinks Tests
func (suite *BrandingHandlerTestSuite) TestToHTTPLinks() {
	links := []Link{
		{Href: "/branding?offset=0&limit=10", Rel: "first"},
		{Href: "/branding?offset=10&limit=10", Rel: "next"},
	}

	httpLinks := toHTTPLinks(links)

	suite.Len(httpLinks, 2)
	suite.Equal("first", httpLinks[0].Rel)
	suite.Equal("next", httpLinks[1].Rel)
}

func (suite *BrandingHandlerTestSuite) TestToHTTPLinks_Empty() {
	links := []Link{}
	httpLinks := toHTTPLinks(links)
	suite.Len(httpLinks, 0)
}

// Test handleError default case
func (suite *BrandingHandlerTestSuite) TestHandleError_DefaultCase() {
	// Create an error with unknown code
	unknownError := &serviceerror.ServiceError{
		Type:             serviceerror.ClientErrorType,
		Code:             "BRD-9999",
		Error:            "Unknown error",
		ErrorDescription: "Unknown error description",
	}

	w := httptest.NewRecorder()
	logger := log.GetLogger()
	handleError(w, logger, unknownError)
	suite.Equal(http.StatusBadRequest, w.Code)
}

// failingResponseWriter is a ResponseWriter that fails on Write
type failingResponseWriter struct {
	http.ResponseWriter
	writeError error
}

func (w *failingResponseWriter) Write(p []byte) (int, error) {
	if w.writeError != nil {
		return 0, w.writeError
	}
	// Make Write fail by returning an error
	return 0, errors.New("write failed")
}
