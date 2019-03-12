package csrf

import "net/http"

type CsrfTokenFetcher interface {
	FetchCsrfToken(url string, currentRequest *http.Request) (*CsrfParameters, error)
}
