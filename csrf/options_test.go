package csrf

import (
	"net/http"
	"reflect"
	"testing"
)

// Tests that options functions are applied to the middleware.
func TestOptions(t *testing.T) {
	var h http.Handler

	age := 86400
	domain := "gorillatoolkit.org"
	path := "/forms/"
	header := "X-AUTH-TOKEN"
	field := "authenticity_token"
	errorHandler := unauthorizedHandler
	name := "_chimpanzee_csrf"

	testOpts := []Option{
		MaxAge(age),
		Domain(domain),
		Path(path),
		HttpOnly(false),
		Secure(false),
		RequestHeader(header),
		FieldName(field),
		ErrorHandler(http.HandlerFunc(errorHandler)),
		CookieName(name),
	}

	// Parse our test options and check that they set the related struct fields.
	cs := parseOptions(h, testOpts...)

	if cs.Opts.MaxAge != age {
		t.Errorf("MaxAge not set correctly: got %v want %v", cs.Opts.MaxAge, age)
	}

	if cs.Opts.Domain != domain {
		t.Errorf("Domain not set correctly: got %v want %v", cs.Opts.Domain, domain)
	}

	if cs.Opts.Path != path {
		t.Errorf("Path not set correctly: got %v want %v", cs.Opts.Path, path)
	}

	if cs.Opts.HttpOnly != false {
		t.Errorf("HttpOnly not set correctly: got %v want %v", cs.Opts.HttpOnly, false)
	}

	if cs.Opts.Secure != false {
		t.Errorf("Secure not set correctly: got %v want %v", cs.Opts.Secure, false)
	}

	if cs.Opts.RequestHeader != header {
		t.Errorf("RequestHeader not set correctly: got %v want %v", cs.Opts.RequestHeader, header)
	}

	if cs.Opts.FieldName != field {
		t.Errorf("FieldName not set correctly: got %v want %v", cs.Opts.FieldName, field)
	}

	if !reflect.ValueOf(cs.Opts.ErrorHandler).IsValid() {
		t.Errorf("ErrorHandler not set correctly: got %v want %v",
			reflect.ValueOf(cs.Opts.ErrorHandler).IsValid(), reflect.ValueOf(errorHandler).IsValid())
	}

	if cs.Opts.CookieName != name {
		t.Errorf("CookieName not set correctly: got %v want %v",
			cs.Opts.CookieName, name)
	}
}
