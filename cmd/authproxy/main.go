package main

import (
	"flag"
	"fmt"
	"sync"

	"github.com/cofyc/authproxy/config"
	"github.com/cofyc/authproxy/middlewares/proxyauth"

	"github.com/gin-gonic/contrib/sessions"
	"github.com/gin-gonic/gin"
	"qiniupkg.com/x/log.v7"
)

var (
	optConfigFile string
)

func init() {
	flag.StringVar(&optConfigFile, "c", "authproxy.yml", "config file")
}

func main() {
	flag.Parse()

	if optConfigFile == "" {
		log.Fatal("no config file")
	}

	c, err := config.LoadFile(optConfigFile)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("global: %#v\n", c.Global)
	for i, proxy := range c.Proxies {
		fmt.Printf("proxies[%d]: %#v\n", i, proxy)
	}

	var wg sync.WaitGroup
	for _, proxy := range c.Proxies {
		wg.Add(1)
		go func(proxy config.ProxyConfig) {
			defer wg.Done()
			// Creates a gin router with default middleware:
			// logger and recovery (crash-free) middleware
			if c.Global.Production {
				gin.SetMode(gin.ReleaseMode)
			}
			r := gin.Default()
			// session
			store := sessions.NewCookieStore([]byte(c.Global.CookieSecret))
			store.Options(sessions.Options{
				MaxAge:   c.Global.CookieMaxAge,
				HttpOnly: true,
			})
			r.Use(sessions.Sessions("AUTHPROXY_SID", store))
			r.Use(proxyauth.ProxyAuth(proxy))
			r.Run(proxy.Listen)
		}(proxy)
	}
	wg.Wait()
}
