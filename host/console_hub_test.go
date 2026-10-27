package host

import (
    "net/http"
    "net/http/httptest"
    "strings"
    "testing"
)

func TestNativeHubConsoleRoutesRetainEmbeddedAssetsAndCSP(t *testing.T) {
    h := &Host{}
    cases := []struct{
        path string
        status int
        content string
    }{
        {"/v1/console", http.StatusPermanentRedirect, ""},
        {"/v1/console/", http.StatusOK, "text/html"},
        {"/v1/console/js/main.js", http.StatusOK, "text/javascript"},
        {"/v1/console/css/app.css", http.StatusOK, "text/css"},
        {"/v1/console/icons/redx-128.png", http.StatusOK, "image/png"},
        {"/v1/console/definitely-missing.js", http.StatusNotFound, ""},
        {"/v1/console/../config.json", http.StatusNotFound, ""},
    }
    for _, tc := range cases {
        t.Run(tc.path, func(t *testing.T){
            req:=httptest.NewRequest(http.MethodGet, "https://api.red-xai.com"+tc.path,nil)
            out:=httptest.NewRecorder()
            h.serveHubConsole(out,req)
            if out.Code != tc.status { t.Fatalf("got %d wanted %d, body: %s",out.Code,tc.status,out.Body.String()) }
            if tc.content != "" && !strings.HasPrefix(out.Header().Get("Content-Type"),tc.content) {
                t.Fatalf("unexpected asset content type: %q",out.Header().Get("Content-Type"))
            }
            if out.Code == http.StatusOK {
                if csp:=out.Header().Get("Content-Security-Policy"); !strings.Contains(csp,"script-src 'self'") ||
                    strings.Contains(csp,"'unsafe-inline'") { t.Fatalf("CSP weakened: %q",csp) }
                if tc.path=="/v1/console/" {
                    body:=out.Body.String()
                    if !strings.Contains(body,`src="./js/main.js"`) ||
                        strings.Contains(body, "forge.css") ||
                        !strings.Contains(body,`href="./css/app.css"`) {
                        t.Fatalf("static overlay remains or native assets missing: %s",body)
                    }
                }
            }
        })
    }
}
func TestNativeHubConsoleRejectsPOSTToStaticResources(t *testing.T){
    h:=&Host{}
    req:=httptest.NewRequest(http.MethodPost,"https://api.red-xai.com/v1/console/js/main.js",nil)
    out:=httptest.NewRecorder()
    h.serveHubConsole(out,req)
    if out.Code!=http.StatusMethodNotAllowed {t.Fatalf("POST on static UI returned %d",out.Code)}
}
