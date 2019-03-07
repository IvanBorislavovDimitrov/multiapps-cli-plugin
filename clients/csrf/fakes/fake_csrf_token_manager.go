package fakes

import "net/http"

const FakeCsrfTokenHeader = "fake-xcsrf-token-header"
const FakeCsrfTokenValue = "fake-xcsrf-token-value"

type FakeCsrfTokenFetcher struct {
}

func (c *FakeCsrfTokenFetcher) FetchNewCsrfToken(url string, currentRequest *http.Request) (string, string, error) {
	return FakeCsrfTokenHeader, FakeCsrfTokenValue, nil
}

func NewFakeCsrfTokenFetcher() *FakeCsrfTokenFetcher {
	return &FakeCsrfTokenFetcher{}
}
