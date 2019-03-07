package csrf

import (
	"net/http"
)

const CookieHeader = "Cookie"

type CookiesUpdater struct {
	cookies []*http.Cookie
	Request *http.Request
}

func NewCookiesUpdater(cookies []*http.Cookie, request *http.Request) *CookiesUpdater {
	return &CookiesUpdater{cookies: cookies, Request: request}
}

func (c *CookiesUpdater) updateCookiesIfNeeded() {
	if c.cookies != nil {
		c.Request.Header.Del(CookieHeader)
		for _, cookie := range c.cookies {
			c.Request.AddCookie(cookie)
		}
	}
}
