package csrf

import "net/http"

type CsrfTokenManager interface {
	setCsrfToken() error
	initializeToken(force bool, url string) error
	isRetryNeeded(response *http.Response) (bool, error)
	updateCurrentCsrfTokens(request *http.Request, t *Transport)
	isProtectionRequired(req *http.Request, t *Transport) bool
}
