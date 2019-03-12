package fakes

import (
	"github.com/cloudfoundry-incubator/multiapps-cli-plugin/clients/csrf"
	"net/http"
)

const FakeCsrfTokenHeader = "fake-xcsrf-token-header"
const FakeCsrfTokenValue = "fake-xcsrf-token-value"

type FakeCsrfTokenFetcher struct {
}

func (c *FakeCsrfTokenFetcher) FetchCsrfToken(url string, currentRequest *http.Request) (*csrf.CsrfParameters, error) {
	return &csrf.CsrfParameters{FakeCsrfTokenHeader, FakeCsrfTokenValue}, nil
}

func NewFakeCsrfTokenFetcher() *FakeCsrfTokenFetcher {
	return &FakeCsrfTokenFetcher{}
}
