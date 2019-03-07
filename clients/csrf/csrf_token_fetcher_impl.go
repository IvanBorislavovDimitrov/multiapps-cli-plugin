package csrf

import (
	"github.com/cloudfoundry/cli/plugin"
	"net/http"
	"os"
)

const CsrfTokenHeaderFetchValue = "Fetch"
const CsrfTokensApi = "/api/v1/csrf-token"

type CsrfTokenFetcherImpl struct {
	transport *Transport
}

func NewCsrfTokenFetcherImpl(transport *Transport) *CsrfTokenFetcherImpl {
	return &CsrfTokenFetcherImpl{transport: transport}
}

func (c *CsrfTokenFetcherImpl) FetchNewCsrfToken(url string, currentRequest *http.Request) (string, string, error) {
	fetchTokenRequest, _ := http.NewRequest(http.MethodGet, url, nil)
	fetchTokenRequest.Header.Set(XCsrfToken, CsrfTokenHeaderFetchValue)
	fetchTokenRequest.Header.Set("Content-Type", "application/json")

	cliConnection := plugin.NewCliConnection(os.Args[1])
	token, _ := cliConnection.AccessToken()

	fetchTokenRequest.Header.Set("Authorization", token)
	NewCookiesUpdater(currentRequest.Cookies(), fetchTokenRequest).updateCookiesIfNeeded()

	response, err := c.transport.Transport.RoundTrip(fetchTokenRequest)
	if err != nil {
		return "", "", err
	}
	if len(response.Cookies()) != 0 {
		fetchTokenRequest.Header.Del(CookieHeader)
		NewCookiesUpdater(response.Cookies(), fetchTokenRequest).updateCookiesIfNeeded()

		c.transport.Csrf.Cookies = fetchTokenRequest.Cookies()

		response, err = c.transport.Transport.RoundTrip(fetchTokenRequest)
	}

	if err != nil {
		return "", "", err
	}

	return response.Header.Get(XCsrfHeader), response.Header.Get(XCsrfToken), nil
}

func getFetchNewTokenUrl(req *http.Request) string {
	return string(req.URL.Scheme) + "://" + string(req.URL.Host) + CsrfTokensApi
}
