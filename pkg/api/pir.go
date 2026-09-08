package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/strfmt"

	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/generated/restapi/operations/pir"
	"github.com/sigstore/rekor/pkg/log"
)

type pirServiceQuery struct {
	PublicContext []byte   `json:"publicContext"`
	QueryBlocks   [][]byte `json:"queryBlocks"`
}
type pirServiceResponse struct {
	ResponseChunks [][]byte `json:"responseChunks"`
}

// GetLogEntryWithPIRHandler returns the entry and inclusion proof for a specified log index
func GetLogEntryWithPIRHandler(params pir.GetLogEntryWithPIRParams) middleware.Responder {
	ctx := params.HTTPRequest.Context()
	log.ContextLogger(ctx).Debugf("[GetLogEntryWithPIRHandler]")

	requestPayload := pirServiceQuery{
		PublicContext: []byte(*params.Entry.PublicContext),
		QueryBlocks:   make([][]byte, len(params.Entry.QueryBlocks)),
	}

	for i, block := range params.Entry.QueryBlocks {
		requestPayload.QueryBlocks[i] = []byte(block)
	}

	bodyBytes, err := json.Marshal(requestPayload)
	if err != nil {
		return handleRekorAPIError(params, http.StatusBadRequest, err, trillianCommunicationError)
	}

	request, err := http.NewRequestWithContext(
		params.HTTPRequest.Context(),
		http.MethodPost,
		"http://host.docker.internal:8787/query",
		bytes.NewReader(bodyBytes),
	)

	if err != nil {
		return pir.NewGetLogEntryWithPIRDefault(http.StatusUnprocessableEntity).
			WithPayload(&models.Error{Code: http.StatusUnprocessableEntity, Message: err.Error()})
	}

	request.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		return pir.NewGetLogEntryWithPIRDefault(http.StatusUnprocessableEntity).WithPayload(&models.Error{Code: http.StatusUnprocessableEntity, Message: err.Error()})
	}

	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return pir.NewGetLogEntryWithPIRDefault(int(response.StatusCode)).WithPayload(&models.Error{Code: int64(response.StatusCode), Message: "pir_service returned a non-200 status"})
	}

	var svcResponse pirServiceResponse
	err = json.NewDecoder(response.Body).Decode(&svcResponse)
	if err != nil {
		return pir.NewGetLogEntryWithPIRDefault(http.StatusInternalServerError).WithPayload(&models.Error{Code: http.StatusInternalServerError, Message: err.Error()})
	}

	responseChunk := make([]strfmt.Base64, len(svcResponse.ResponseChunks))
	for i, chunk := range svcResponse.ResponseChunks {
		responseChunk[i] = strfmt.Base64(chunk)
	}

	return pir.NewGetLogEntryWithPIROK().WithPayload(&models.PirResponse{
		ResponseChunks: responseChunk,
	})
}

func GetLogEntryWithPIRNotImplementedHandler(_ pir.GetLogEntryWithPIRParams) middleware.Responder {
	err := &models.Error{
		Code:    http.StatusNotImplemented,
		Message: "Get Log Entry with PIR API not enabled in this Rekor instance",
	}

	return pir.NewGetLogEntryWithPIRDefault(http.StatusNotImplemented).WithPayload(err)
}
