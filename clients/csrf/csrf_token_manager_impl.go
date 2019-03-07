package csrf

import (
	"net/http"
)

const XCsrfHeader = "X-Csrf-Header"
const XCsrfToken = "X-Csrf-Token"
const CsrfTokenHeaderRequiredValue = "Required"

type CsrfTokenManagerImpl struct {
	request          *http.Request
	transport        *Transport
	csrfTokenFetcher CsrfTokenFetcher
}

func NewCsrfTokenManagerImpl(transport *Transport, request *http.Request, csrfTokenFetcher CsrfTokenFetcher) *CsrfTokenManagerImpl {
	return &CsrfTokenManagerImpl{request: request, transport: transport, csrfTokenFetcher: csrfTokenFetcher}
}

func (c *CsrfTokenManagerImpl) setCsrfToken() error {
	if c.request == nil || !c.isProtectionRequired(c.request, c.transport) {
		return nil
	}
	err := c.initializeToken(false, getFetchNewTokenUrl(c.request))
	if err != nil {
		return err
	}

	c.updateCurrentCsrfTokens(c.request, c.transport)

	return nil
}

func (c *CsrfTokenManagerImpl) initializeToken(force bool, url string) error {
	if force || !c.transport.Csrf.IsInitialized {
		var err error
		c.transport.Csrf.Header, c.transport.Csrf.Token, err = c.csrfTokenFetcher.FetchNewCsrfToken(url, c.request)
		if err != nil {
			return err
		}
		c.transport.Csrf.IsInitialized = true
	}

	return nil
}

func (c *CsrfTokenManagerImpl) isRetryNeeded(response *http.Response) (bool, error) {
	if !c.isProtectionRequired(c.request, c.transport) {
		return false, nil
	}
	if c.transport.Csrf.IsInitialized && (response.StatusCode == http.StatusForbidden) {
		csrfToken := response.Header.Get(XCsrfToken)

		if CsrfTokenHeaderRequiredValue == csrfToken {
			err := c.initializeToken(true, getFetchNewTokenUrl(c.request))
			if err != nil {
				return false, err
			}

			return c.transport.Csrf.Token != "", nil
		}
	}

	return false, nil
}

func (c *CsrfTokenManagerImpl) updateCurrentCsrfTokens(request *http.Request, t *Transport) {
	if c.transport.Csrf.Token != "" && c.transport.Csrf.Header != "" {
		request.Header.Set(XCsrfToken, t.Csrf.Token)
		request.Header.Set(XCsrfHeader, t.Csrf.Header)
	}
}

func (c *CsrfTokenManagerImpl) isProtectionRequired(req *http.Request, t *Transport) bool {
	return !t.Csrf.NonProtectedMethods[req.Method]
}
