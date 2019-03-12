package csrf

import (
	"github.com/cloudfoundry-incubator/multiapps-cli-plugin/clients/csrf/fakes"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"net/http"
)

const testUrl = "http://localhost:1000"

const csrfTokenNotSet = ""

var _ = Describe("CsrfTokenUpdaterImpl", func() {
	Context("", func() {
		It("protection not needed", func() {
			transport, request := createTransport(), createRequest(http.MethodGet)
			csrfTokenManager := NewCsrfTokenUpdaterImpl(transport, request, NewCsrfTokenFetcherImpl(transport))
			Expect(csrfTokenManager.isProtectionRequired(request, transport)).To(BeFalse())
		})
		It("protection not needed", func() {
			transport, request := createTransport(), createRequest(http.MethodOptions)
			csrfTokenManager := NewCsrfTokenUpdaterImpl(transport, request, NewCsrfTokenFetcherImpl(transport))
			Expect(csrfTokenManager.isProtectionRequired(request, transport)).To(BeFalse())
		})
		It("protection not needed", func() {
			transport, request := createTransport(), createRequest(http.MethodHead)
			csrfTokenManager := NewCsrfTokenUpdaterImpl(transport, request, NewCsrfTokenFetcherImpl(transport))
			Expect(csrfTokenManager.isProtectionRequired(request, transport)).To(BeFalse())
		})
		It("protection needed", func() {
			transport, request := createTransport(), createRequest(http.MethodPost)
			csrfTokenManager := NewCsrfTokenUpdaterImpl(transport, request, NewCsrfTokenFetcherImpl(transport))
			Expect(csrfTokenManager.isProtectionRequired(request, transport)).To(BeTrue())
		})
		It("retry is not needed", func() {
			transport, request := createTransport(), createRequest(http.MethodPost)
			csrfTokenManager := NewCsrfTokenUpdaterImpl(transport, request, NewCsrfTokenFetcherImpl(transport))
			Expect(csrfTokenManager.isRetryNeeded(createResponse(http.StatusOK, ""))).To(BeFalse())
		})
		It("retry is not needed", func() {
			transport, request := createTransport(), createRequest(http.MethodPost)
			csrfTokenManager := NewCsrfTokenUpdaterImpl(transport, request, NewCsrfTokenFetcherImpl(transport))
			Expect(csrfTokenManager.isRetryNeeded(createResponse(http.StatusForbidden, CsrfTokenHeaderRequiredValue))).To(BeFalse())
		})
		It("retry is needed", func() {
			transport := createTransport()
			transport.Csrf.IsInitialized = true
			request := createRequest(http.MethodPost)
			csrfTokenManager := NewCsrfTokenUpdaterImpl(transport, request, fakes.NewFakeCsrfTokenFetcher())
			isRetryNeeded, err := csrfTokenManager.isRetryNeeded(createResponse(http.StatusForbidden, CsrfTokenHeaderRequiredValue))
			Ω(err).ShouldNot(HaveOccurred())
			Expect(isRetryNeeded).To(BeTrue())
		})
		It("initialize new token", func() {
			transport := createTransport()
			transport.Csrf.IsInitialized = true
			request := createRequest(http.MethodPost)
			csrfTokenManager := NewCsrfTokenUpdaterImpl(transport, request, fakes.NewFakeCsrfTokenFetcher())
			err := csrfTokenManager.initializeToken(true, testUrl)
			Ω(err).ShouldNot(HaveOccurred())
			Expect(transport.Csrf.Header).To(Equal(fakes.FakeCsrfTokenHeader))
			Expect(transport.Csrf.Token).To(Equal(fakes.FakeCsrfTokenValue))
			Expect(transport.Csrf.IsInitialized).To(BeTrue())
		})
		It("update current csrf tokens", func() {
			transport := createTransport()
			request := createRequest(http.MethodGet)
			csrfTokenManager := NewCsrfTokenUpdaterImpl(transport, request, fakes.NewFakeCsrfTokenFetcher())
			err := csrfTokenManager.initializeToken(true, testUrl)
			Ω(err).ShouldNot(HaveOccurred())
			csrfTokenManager.updateCurrentCsrfToken(request, transport)
			expectCsrfTokenIsProperlySet(request, fakes.FakeCsrfTokenHeader, fakes.FakeCsrfTokenValue)
		})
		It("should not update csrf tokens", func() {
			transport, request := createTransport(), createRequest(http.MethodGet)
			csrfTokenManager := NewCsrfTokenUpdaterImpl(transport, request, fakes.NewFakeCsrfTokenFetcher())
			err := csrfTokenManager.checkAndUpdateCsrfToken()
			Ω(err).ShouldNot(HaveOccurred())
			expectCsrfTokenIsProperlySet(request, csrfTokenNotSet, csrfTokenNotSet)
		})
		It("should not update csrf tokens", func() {
			transport, request := createTransport(), createRequest(http.MethodPost)
			transport.Csrf.IsInitialized = true
			csrfTokenManager := NewCsrfTokenUpdaterImpl(transport, request, fakes.NewFakeCsrfTokenFetcher())
			err := csrfTokenManager.checkAndUpdateCsrfToken()
			Ω(err).ShouldNot(HaveOccurred())
			expectCsrfTokenIsProperlySet(request, csrfTokenNotSet, csrfTokenNotSet)
		})
		It("should not update csrf tokens", func() {
			transport, request := createTransport(), createRequest(http.MethodGet)
			csrfTokenManager := NewCsrfTokenUpdaterImpl(transport, request, fakes.NewFakeCsrfTokenFetcher())
			err := csrfTokenManager.checkAndUpdateCsrfToken()
			Ω(err).ShouldNot(HaveOccurred())
			expectCsrfTokenIsProperlySet(request, csrfTokenNotSet, csrfTokenNotSet)
		})
		It("should update csrf tokens", func() {
			transport, request := createTransport(), createRequest(http.MethodPost)
			csrfTokenManager := NewCsrfTokenUpdaterImpl(transport, request, fakes.NewFakeCsrfTokenFetcher())
			err := csrfTokenManager.checkAndUpdateCsrfToken()
			Ω(err).ShouldNot(HaveOccurred())
			expectCsrfTokenIsProperlySet(request, fakes.FakeCsrfTokenHeader, fakes.FakeCsrfTokenValue)
		})
	})
})

func expectCsrfTokenIsProperlySet(request *http.Request, csrfTokenHeader, csrfTokenValue string) {
	Expect(request.Header.Get(XCsrfHeader)).To(Equal(csrfTokenHeader))
	Expect(request.Header.Get(XCsrfToken)).To(Equal(csrfTokenValue))
}

func createResponse(httpStatusCode int, csrfToken string) *http.Response {
	response := &http.Response{}
	response.Header = make(http.Header)
	response.StatusCode = httpStatusCode
	response.Header.Set(XCsrfToken, csrfToken)

	return response
}

func createTransport() *Transport {
	return &Transport{http.DefaultTransport.(*http.Transport),
		&Csrf{"", "", false, getNonProtectedMethods()}, &Cookies{[]*http.Cookie{}}}
}

func getNonProtectedMethods() map[string]bool {
	nonProtectedMethods := make(map[string]bool)

	nonProtectedMethods[http.MethodGet] = true
	nonProtectedMethods[http.MethodHead] = true
	nonProtectedMethods[http.MethodOptions] = true

	return nonProtectedMethods
}
