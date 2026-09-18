package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/strfmt"

	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/generated/restapi/operations/pir"
	"github.com/sigstore/rekor/pkg/log"
	pirsvc "github.com/sigstore/rekor/pkg/pir"
)

type pirServiceQuery struct {
	PublicContext []byte   `json:"publicContext"`
	QueryBlocks   [][]byte `json:"queryBlocks"`
}

type pirServiceResponse struct {
	ResponseChunks [][]byte `json:"responseChunks"`
}

func GetLogEntryWithPIRHandler(params pir.GetLogEntryWithPIRParams) middleware.Responder {
	ctx := params.HTTPRequest.Context()
	log.ContextLogger(ctx).Debugf("[GetLogEntryWithPIRHandler]")

	request, err := BuildQueryHttpRequest(ctx, params.Entry)
	if err != nil {
		return pir.NewGetLogEntryWithPIRDefault(http.StatusUnprocessableEntity).WithPayload(
			&models.Error{Code: http.StatusBadRequest, Message: err.Error()})
	}

	client := &http.Client{Timeout: pirsvc.PIRServiceTimeout}
	response, err := client.Do(request)
	if err != nil {
		return pir.NewGetLogEntryWithPIRDefault(http.StatusUnprocessableEntity).WithPayload(
			&models.Error{Code: http.StatusInternalServerError, Message: err.Error()})
	}

	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return pir.NewGetLogEntryWithPIRDefault(int(response.StatusCode)).WithPayload(
			&models.Error{Code: int64(response.StatusCode), Message: "pir_service returned a non-200 status"})
	}

	pirResponse, err := BuildResponseFromHttpResponse(response)
	if err != nil {
		return pir.NewGetLogEntryWithPIRDefault(http.StatusInternalServerError).WithPayload(
			&models.Error{Code: http.StatusInternalServerError, Message: err.Error()})
	}

	return pir.NewGetLogEntryWithPIROK().WithPayload(pirResponse)
}

func BuildResponseFromHttpResponse(response *http.Response) (*models.PirResponse, error) {
	var svcResponse pirServiceResponse
	err := json.NewDecoder(response.Body).Decode(&svcResponse)
	if err != nil {
		return nil, err
	}

	responseChunk := make([]strfmt.Base64, len(svcResponse.ResponseChunks))
	for i, chunk := range svcResponse.ResponseChunks {
		responseChunk[i] = strfmt.Base64(chunk)
	}

	return &models.PirResponse{ResponseChunks: responseChunk}, nil
}

func BuildQueryHttpRequest(ctx context.Context, pirQuery *models.PirQuery) (*http.Request, error) {
	requestPayload := pirServiceQuery{
		PublicContext: []byte(*pirQuery.PublicContext),
		QueryBlocks:   make([][]byte, len(pirQuery.QueryBlocks)),
	}

	for i, block := range pirQuery.QueryBlocks {
		requestPayload.QueryBlocks[i] = []byte(block)
	}

	bodyBytes, err := json.Marshal(requestPayload)
	if err != nil {
		return nil, err
	}

	pirQueryURL := fmt.Sprint("http://", pirsvc.PIRServiceHost, ":", pirsvc.PIRServicePort, pirsvc.PIRServiceQueryPath)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, pirQueryURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}

	request.Header.Set("Content-Type", "application/json")

	return request, nil
}

func GetLogEntryWithPIRNotImplementedHandler(_ pir.GetLogEntryWithPIRParams) middleware.Responder {
	err := &models.Error{
		Code:    http.StatusNotImplemented,
		Message: "Get Log Entry with PIR API not enabled in this Rekor instance",
	}

	return pir.NewGetLogEntryWithPIRDefault(http.StatusNotImplemented).WithPayload(err)
}
