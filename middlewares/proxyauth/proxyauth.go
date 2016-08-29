package proxyauth

import (
	"container/ring"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"

	"github.com/cofyc/authproxy/config"

	"github.com/gin-gonic/contrib/sessions"
	"github.com/gin-gonic/gin"
	"qiniupkg.com/x/log.v7"
)

func signinUrlFromReq(req *http.Request) string {
	u := &url.URL{}
	*u = *req.URL
	u.Scheme = "http"
	u.Host = req.Host
	v := u.Query()
	v.Set("__authproxy", "cas")
	u.RawQuery = v.Encode()
	return u.String()
}

type CasResult struct {
	Success struct {
		User  string `xml:"user"`
		Attrs struct {
			Email string `xml:"email"`
		} `xml:"attributes"`
	} `xml:"authenticationSuccess"`
}

type CasService struct {
	url *url.URL
}

func (cas *CasService) CopyUrl() *url.URL {
	u := &url.URL{}
	*u = *cas.url
	return u
}

func (cas *CasService) GenerateLoginUrl(service string) string {
	v := url.Values{}
	v.Set("service", service)
	loginUrl := cas.CopyUrl()
	loginUrl.Path = "/login"
	loginUrl.RawQuery = v.Encode()
	return loginUrl.String()
}

func (cas *CasService) GenerateValidateUrl(service, ticket string) string {
	v := url.Values{}
	v.Set("ticket", ticket)
	v.Set("service", service)
	validateUrl := cas.CopyUrl()
	validateUrl.Path = "/serviceValidate"
	validateUrl.RawQuery = v.Encode()
	return validateUrl.String()
}

func (cas *CasService) ValidateTicket(service, ticket string) (casResult *CasResult, err error) {
	casResult = &CasResult{}
	validateUrl := cas.GenerateValidateUrl(service, ticket)
	resp, err := http.Get(validateUrl)
	if err != nil {
		log.Println(err)
		return
	}

	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Println(err)
		return
	}

	log.Infof("raw: %s", string(b))
	err = xml.Unmarshal(b, &casResult)
	if err != nil {
		log.Println(err)
		return
	}

	return
}

func NewCasService(server string) (cas *CasService, err error) {
	u, err := url.Parse(server)
	if err != nil {
		return
	}
	return &CasService{
		url: u,
	}, nil
}

type (
	authPair struct {
		Value string
		User  string
	}
	authPairs []authPair
)

func (a authPairs) SearchCredential(authValue string) (string, bool) {
	for _, pair := range a {
		if pair.Value == authValue {
			return pair.User, true
		}
	}
	return "", false
}

func authValue(user, pass string) string {
	base := fmt.Sprintf("%s:%s", user, pass)
	return fmt.Sprintf("Basic %s", base64.StdEncoding.EncodeToString([]byte(base)))
}

func NewAuthPairs(auths map[string]string) authPairs {
	pairs := make(authPairs, 0, len(auths))
	for u, pass := range auths {
		pairs = append(pairs, authPair{
			User:  u,
			Value: authValue(u, pass),
		})
	}
	return pairs
}

func ProxyAuth(cfg config.ProxyConfig) gin.HandlerFunc {
	r := ring.New(len(cfg.Backends))
	for _, b := range cfg.Backends {
		u, err := url.Parse(b)
		if err != nil {
			log.Fatal(err)
		}
		if u.Scheme == "" {
			log.Fatalf("backend should have url schema: %s", b)
		}
		r.Value = u
		r = r.Next()
	}
	basicAuthPairs := NewAuthPairs(cfg.BasicAuths)
	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			target := r.Value.(*url.URL)
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			req.URL.Path = path.Join(target.Path, req.URL.Path)
			targetQuery := target.RawQuery
			if targetQuery == "" || req.URL.RawQuery == "" {
				req.URL.RawQuery = targetQuery + req.URL.RawQuery
			} else {
				req.URL.RawQuery = targetQuery + "&" + req.URL.RawQuery
			}
			if _, ok := req.Header["User-Agent"]; !ok {
				// explicitly disable User-Agent so it's not set to default value
				req.Header.Set("User-Agent", "")
			}
			r = r.Next()
		},
	}
	cas, err := NewCasService(cfg.CasServerUrl)
	if err != nil {
		log.Fatal(err)
	}
	return func(c *gin.Context) {
		w := c.Writer
		r := c.Request
		// check user logined or not
		session := sessions.Default(c)
		user := session.Get("user")
		log.Infof("user: %#v", user)
		if user != nil {
			if v, ok := user.(string); ok && v != "" {
				proxy.ServeHTTP(w, r)
				return
			} else {
				// clear
				session.Delete("user")
				session.Save()
			}
		}
		// check basic auth first
		basicUser, found := basicAuthPairs.SearchCredential(r.Header.Get("Authorization"))
		if found {
			session.Set("user", basicUser)
			session.Save()
			proxy.ServeHTTP(w, r)
			return
		}
		// then try cas
		service := signinUrlFromReq(r)
		loginUrl := cas.GenerateLoginUrl(service)
		if r.URL.Query().Get("__authproxy") == "cas" {
			// try validate ticket
			res, err := cas.ValidateTicket(service, r.URL.Query().Get("ticket"))
			if err != nil {
				goto unauth
			}
			if res.Success.User == "" {
				goto retry
			} else {
				session.Set("user", res.Success.User)
				session.Save()
				http.Redirect(w, r, "/", http.StatusFound)
				return
			}
		}
	retry:
		http.Redirect(w, r, loginUrl, http.StatusFound)
		return
	unauth:
		c.AbortWithStatus(401)
		return
	}
}
