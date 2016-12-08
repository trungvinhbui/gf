package csrf

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/goframework/gf/securecookie"
)

// CSRF token length in bytes.
const TokenLength = 32

// Context/session keys & prefixes
const (
	TokenKey   string = "csrf.Token"
	FormKey    string = "csrf.Form"
	ErrorKey   string = "csrf.Error"
	CookieName string = "_csrf"
)

var (
	// The name value used in form fields.
	fieldName = TokenKey
	// defaultAge sets the default MaxAge for cookies.
	defaultAge = 3600 * 12
	// The default HTTP request header to inspect
	headerName = "X-CSRF-Token"
	// Idempotent (safe) methods as defined by RFC7231 section 4.2.2.
	SafeMethods = []string{"GET", "HEAD", "OPTIONS", "TRACE"}
)

// TemplateTag provides a default template tag - e.g. {{ .csrfField }} - for use
// with the TemplateField function.
var TemplateTag = "csrfField"

var (
	// ErrNoReferer is returned when a HTTPS request provides an empty Referer
	// header.
	ErrNoReferer = errors.New("referer not supplied")
	// ErrBadReferer is returned when the scheme & host in the URL do not match
	// the supplied Referer header.
	ErrBadReferer = errors.New("referer invalid")
	// ErrNoToken is returned if no CSRF token is supplied in the request.
	ErrNoToken = errors.New("CSRF token not found in request")
	// ErrBadToken is returned if the CSRF token in the request does not match
	// the token in the session, or is otherwise malformed.
	ErrBadToken = errors.New("CSRF token invalid")
)

type CsrfProtection struct {
	h    http.Handler
	Sc   *securecookie.SecureCookie
	St   store
	Opts options
}

// options contains the optional settings for the CSRF middleware.
type options struct {
	MaxAge int
	Domain string
	Path   string
	// Note that the function and field names match the case of the associated
	// http.Cookie field instead of the "correct" HTTPOnly name that golint suggests.
	HttpOnly      bool
	Secure        bool
	RequestHeader string
	FieldName     string
	ErrorHandler  http.Handler
	CookieName    string
}

// unauthorizedhandler sets a HTTP 403 Forbidden status and writes the
// CSRF failure reason to the response.
func unauthorizedHandler(w http.ResponseWriter, r *http.Request) {
	http.Error(w, fmt.Sprintf("%s - %s",
		http.StatusText(http.StatusForbidden), FailureReason(r)),
		http.StatusForbidden)
	return
}

func InitCsrf(authKey []byte, opts ...Option) *CsrfProtection {
	cs := parseOptions(nil, opts...)

	// Set the defaults if no options have been specified
	if cs.Opts.ErrorHandler == nil {
		cs.Opts.ErrorHandler = http.HandlerFunc(unauthorizedHandler)
	}

	if cs.Opts.MaxAge < 1 {
		// Default of 12 hours
		cs.Opts.MaxAge = defaultAge
	}

	if cs.Opts.FieldName == "" {
		cs.Opts.FieldName = fieldName
	}

	if cs.Opts.CookieName == "" {
		cs.Opts.CookieName = CookieName
	}

	if cs.Opts.RequestHeader == "" {
		cs.Opts.RequestHeader = headerName
	}

	// Create an authenticated securecookie instance.
	if cs.Sc == nil {
		cs.Sc = securecookie.New(authKey, nil)
		// Use JSON serialization (faster than one-off gob encoding)
		cs.Sc.SetSerializer(securecookie.JSONEncoder{})
		// Set the MaxAge of the underlying securecookie.
		cs.Sc.MaxAge(cs.Opts.MaxAge)
	}

	if cs.St == nil {
		// Default to the cookieStore
		cs.St = &cookieStore{
			name:     cs.Opts.CookieName,
			maxAge:   cs.Opts.MaxAge,
			secure:   cs.Opts.Secure,
			httpOnly: cs.Opts.HttpOnly,
			path:     cs.Opts.Path,
			domain:   cs.Opts.Domain,
			sc:       cs.Sc,
		}
	}

	return cs
}
