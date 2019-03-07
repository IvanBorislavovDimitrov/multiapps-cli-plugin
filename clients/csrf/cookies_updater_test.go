package csrf

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"net/http"
	"net/url"
)

var _ = Describe("CookiesUpdater", func() {
	Context("set cookies in the request, valid cookies", func() {
		It("should be equal", func() {
			request := createRequest(http.MethodGet)
			cookies := createValidCookies()
			createCookiesUpdater(cookies, request).updateCookiesIfNeeded()
			Expect(cookies).To(Equal(request.Cookies()))
		})
	})

	Context("set cookies in the request, no cookies", func() {
		It("should not add cookies", func() {
			request := createRequest(http.MethodGet)
			cookies := []*http.Cookie{}
			createCookiesUpdater(cookies, request).updateCookiesIfNeeded()
			Expect(cookies).To(Equal(request.Cookies()))
		})
	})
})

func createCookiesUpdater(cookies []*http.Cookie, request *http.Request) *CookiesUpdater {
	return &CookiesUpdater{cookies: cookies, Request: request}
}

func createValidCookies() []*http.Cookie {
	var cookies []*http.Cookie
	cookie1 := &http.Cookie{}
	cookie1.Name = "JSESSION"
	cookie1.Value = "123"
	cookie2 := &http.Cookie{}
	cookie2.Name = "__V_CAP__"
	cookie2.Value = "321"
	cookies = append(cookies, cookie1)
	cookies = append(cookies, cookie2)

	return cookies
}

func createRequest(method string) *http.Request {
	request := &http.Request{}
	requestUrl := &url.URL{}
	requestUrl.Scheme = "http"
	requestUrl.Host = "localhost:1000"
	request.URL = requestUrl
	request.Header = make(http.Header)
	request.Method = method

	return request
}
