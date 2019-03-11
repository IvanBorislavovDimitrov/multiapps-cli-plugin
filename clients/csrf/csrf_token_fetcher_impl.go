package csrf

import (
	"github.com/cloudfoundry/cli/plugin"
	"net/http"
	"os"
)

const CsrfTokenHeaderFetchValue = "Fetch"
const CsrfTokensApi = "/api/v1/csrf-token"
const ContentTypeHeader = "Content-Type"
const AuthorizationHeader = "Authorization"
const ApplicationJsonContentType = "application/json"
const CookieHeader = "CookieHeader"

type CsrfTokenFetcherImpl struct {
	transport *Transport
}

func NewCsrfTokenFetcherImpl(transport *Transport) *CsrfTokenFetcherImpl {
	return &CsrfTokenFetcherImpl{transport: transport}
}

func (c *CsrfTokenFetcherImpl) FetchCsrfToken(url string, currentRequest *http.Request) (string, string, error) {
	fetchTokenRequest, _ := http.NewRequest(http.MethodGet, url, nil)
	fetchTokenRequest.Header.Set(XCsrfToken, CsrfTokenHeaderFetchValue)
	fetchTokenRequest.Header.Set(ContentTypeHeader, ApplicationJsonContentType)

	cliConnection := plugin.NewCliConnection(os.Args[1])
	token, _ := cliConnection.AccessToken()

	fetchTokenRequest.Header.Set(AuthorizationHeader, token)
	UpdateCookiesIfNeeded(currentRequest.Cookies(), fetchTokenRequest)

	response, err := c.transport.Transport.RoundTrip(fetchTokenRequest)
	if err != nil {
		return "", "", err
	}
	if len(response.Cookies()) != 0 {
		fetchTokenRequest.Header.Del(CookieHeader)
		UpdateCookiesIfNeeded(response.Cookies(), fetchTokenRequest)

		c.transport.Csrf.Cookies = fetchTokenRequest.Cookies()

		response, err = c.transport.Transport.RoundTrip(fetchTokenRequest)

		if err != nil {
			return "", "", err
		}
	}

	return response.Header.Get(XCsrfHeader), response.Header.Get(XCsrfToken), nil
}

func getCsrfTokenUrl(req *http.Request) string {
	return string(req.URL.Scheme) + "://" + string(req.URL.Host) + CsrfTokensApi
}

func UpdateCookiesIfNeeded(cookies []*http.Cookie, request *http.Request) {
	if cookies != nil {
		request.Header.Del(CookieHeader)
		for _, cookie := range cookies {
			request.AddCookie(cookie)
		}
	}
}
