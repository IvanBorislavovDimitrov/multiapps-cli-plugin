package csrf

import "net/http"

type CsrfTokenFetcher interface {
	FetchNewCsrfToken(url string, currentRequest *http.Request) (string, string, error)
}
