package csrf

import (
	"net/http"
)

const XCsrfHeader = "X-Csrf-Header"
const XCsrfToken = "X-Csrf-Token"
const CsrfTokenHeaderRequiredValue = "Required"

type CsrfTokenUpdaterImpl struct {
	request          *http.Request
	transport        *Transport
	csrfTokenFetcher CsrfTokenFetcher
}

func NewCsrfTokenUpdaterImpl(transport *Transport, request *http.Request, csrfTokenFetcher CsrfTokenFetcher) *CsrfTokenUpdaterImpl {
	return &CsrfTokenUpdaterImpl{request: request, transport: transport, csrfTokenFetcher: csrfTokenFetcher}
}

func (c *CsrfTokenUpdaterImpl) checkAndUpdateCsrfToken() error {
	if c.request == nil || !c.isProtectionRequired(c.request, c.transport) {
		return nil
	}
	err := c.initializeToken(false, getCsrfTokenUrl(c.request))
	if err != nil {
		return err
	}

	c.updateCurrentCsrfToken(c.request, c.transport)

	return nil
}

func (c *CsrfTokenUpdaterImpl) initializeToken(forceInitializing bool, url string) error {
	if forceInitializing || !c.transport.Csrf.IsInitialized {
		var err error
		csrfParameters, err := c.csrfTokenFetcher.FetchCsrfToken(url, c.request)
		c.transport.Csrf.Header, c.transport.Csrf.Token = csrfParameters.csrfTokenHeader, csrfParameters.csrfTokenValue

		if err != nil {
			return err
		}
		c.transport.Csrf.IsInitialized = true
	}

	return nil
}

func (c *CsrfTokenUpdaterImpl) isRetryNeeded(response *http.Response) (bool, error) {
	if !c.isProtectionRequired(c.request, c.transport) {
		return false, nil
	}
	if c.transport.Csrf.IsInitialized && (response.StatusCode == http.StatusForbidden) {
		csrfToken := response.Header.Get(XCsrfToken)

		if CsrfTokenHeaderRequiredValue == csrfToken {
			err := c.initializeToken(true, getCsrfTokenUrl(c.request))
			if err != nil {
				return false, err
			}

			return c.transport.Csrf.Token != "", nil
		}
	}

	return false, nil
}

func (c *CsrfTokenUpdaterImpl) updateCurrentCsrfToken(request *http.Request, t *Transport) {
	if c.transport.Csrf.Token != "" && c.transport.Csrf.Header != "" {
		request.Header.Set(XCsrfToken, t.Csrf.Token)
		request.Header.Set(XCsrfHeader, t.Csrf.Header)
	}
}

func (c *CsrfTokenUpdaterImpl) isProtectionRequired(req *http.Request, t *Transport) bool {
	return !t.Csrf.NonProtectedMethods[req.Method]
}
