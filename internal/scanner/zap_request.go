package scanner

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// Keep each request variant distinct, including methods sharing one URL.
func zapSelectedRequests(req Request) []ScannerRequestInput {
	if len(req.InputRequests) > 0 {
		return req.InputRequests
	}
	var inputs []ScannerRequestInput
	for _, raw := range requestEndpointTargets(req) {
		method := req.EndpointMethods[raw]
		if method == "" {
			method = http.MethodGet
		}
		inputs = append(inputs, ScannerRequestInput{URL: raw, Method: method, Selected: true})
	}
	return inputs
}

func zapRequestMessage(input ScannerRequestInput) (string, error) {
	method := input.Method
	if method == "" {
		method = http.MethodGet
	}
	r, err := http.NewRequest(method, input.URL, strings.NewReader(input.Body))
	if err != nil {
		return "", err
	}
	if r.URL.User != nil || r.URL.Host == "" || (r.URL.Scheme != "http" && r.URL.Scheme != "https") {
		return "", fmt.Errorf("invalid request destination")
	}
	if strings.ContainsAny(input.ContentType, "\r\n") {
		return "", fmt.Errorf("invalid request content type")
	}
	// Absolute URI retains HTTPS and encoded request semantics in ZAP sendRequest.
	message := method + " " + r.URL.String() + " HTTP/1.1\r\nHost: " + r.URL.Host + "\r\n"
	if input.ContentType != "" {
		message += "Content-Type: " + input.ContentType + "\r\n"
	}
	if input.Body != "" {
		message += "Content-Length: " + strconv.Itoa(len(input.Body)) + "\r\n"
	}
	return message + "\r\n" + input.Body, nil
}

func zapSeedRequest(ctx context.Context, cfg Config, call zapCallFunc, input ScannerRequestInput) error {
	if (input.Method == "" || input.Method == http.MethodGet) && input.Body == "" {
		_, err := call("/JSON/core/action/accessUrl/", url.Values{"url": {input.URL}, "followRedirects": {"false"}})
		return err
	}
	message, err := zapRequestMessage(input)
	if err != nil {
		return err
	}
	// The body may contain replay credentials. Never put it in an API URL.
	_, err = zapPostResponse(ctx, cfg, "/JSON/core/action/sendRequest/", url.Values{"request": {message}, "followRedirects": {"false"}})
	return err
}
