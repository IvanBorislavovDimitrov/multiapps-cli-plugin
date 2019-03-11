package csrf

import (
	"github.com/jinzhu/copier"
	"net/http"
)

type Csrf struct {
	Header              string
	Token               string
	IsInitialized       bool
	Cookies             []*http.Cookie
	NonProtectedMethods map[string]bool
}

type Transport struct {
	Transport http.RoundTripper
	Csrf      *Csrf
}

func (t Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	req2 := http.Request{}
	copier.Copy(&req2, req)

	UpdateCookiesIfNeeded(t.Csrf.Cookies, &req2)

	csrfTokenManager := NewCsrfTokenManagerImpl(&t, &req2, NewCsrfTokenFetcherImpl(&t))

	err := csrfTokenManager.checkAndUpdateCsrfToken()
	if err != nil {
		return nil, err
	}

	res, err := t.Transport.RoundTrip(&req2)
	if err != nil {
		return nil, err
	}
	isRetryNeeded, err := csrfTokenManager.isRetryNeeded(res)
	if err != nil {
		return nil, err
	}

	if isRetryNeeded {
		return res, &ForbiddenError{}
	}

	return res, err
}
