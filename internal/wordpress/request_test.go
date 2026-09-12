package wordpress

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/go-chi/chi/v5"
)

// requestWithID builds a request whose chi route carries a domain id.
func requestWithID(method, target, body, id string) *http.Request {
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	routeCtx := chi.NewRouteContext()
	routeCtx.URLParams.Add("id", id)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, routeCtx))
}
