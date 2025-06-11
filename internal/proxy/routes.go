package proxy

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Route represents one entry from routes.yaml
type Route struct {
	Prefix          string `yaml:"prefix"`
	Upstream        string `yaml:"upstream"`
	CopySubProtocol bool   `yaml:"copySubProtocol"`
	PreserveQuery   bool   `yaml:"preserveQuery"`
}

// loadRoutes reads /etc/ws-gw/routes.yaml (path is passed via flag/env)
func loadRoutes(path string) ([]Route, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var routes []Route
	return routes, yaml.Unmarshal(b, &routes)
}

// upstreamFor returns the upstream URL + headers for a given request
func upstreamFor(req *http.Request, routes []Route) (string, http.Header, error) {
	for _, r := range routes {
		if strings.HasPrefix(req.URL.Path, r.Prefix) {
			u, _ := url.Parse(r.Upstream)
      
			if r.PreserveQuery {
				u.RawQuery = req.URL.RawQuery
			}
      
			h := http.Header{}
      
			if r.CopySubProtocol {
				if sp := req.Header.Get("Sec-WebSocket-Protocol"); sp != "" {
					h.Set("Sec-WebSocket-Protocol", sp)
				}
			}
      
			return u.String(), h, nil
		}
	}
  
	return "", nil, fmt.Errorf("no match for %s", req.URL.Path)
}
