package fakes

import (
	"github.com/cloudfoundry-incubator/multiapps-cli-plugin/clients/csrf/csrf_paramters"
	"net/http"
)

const FakeCsrfTokenHeader = "fake-xcsrf-token-header"
const FakeCsrfTokenValue = "fake-xcsrf-token-value"

type FakeCsrfTokenFetcher struct {
}

func (c *FakeCsrfTokenFetcher) FetchCsrfToken(url string, currentRequest *http.Request) (*csrf_paramters.CsrfParameters, error) {
	return &csrf_paramters.CsrfParameters{FakeCsrfTokenHeader, FakeCsrfTokenValue}, nil
}

func NewFakeCsrfTokenFetcher() *FakeCsrfTokenFetcher {
	return &FakeCsrfTokenFetcher{}
}
