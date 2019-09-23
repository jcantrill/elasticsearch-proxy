package main

import (
	"io/ioutil"
	"net/http"
	_ "net/http/pprof"
	"os"
	"strings"

	"github.com/openshift/elasticsearch-proxy/pkg/config"
	auth "github.com/openshift/elasticsearch-proxy/pkg/handlers/authorization"
	cl "github.com/openshift/elasticsearch-proxy/pkg/handlers/clusterlogging"
	"github.com/openshift/elasticsearch-proxy/pkg/proxy"
	log "github.com/openshift/elasticsearch-proxy/pkg/logging"
)

const (
	serviceAccountTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
)

func main() {

	opts, err := config.Init(os.Args[1:])
	if err != nil {
		log.Printf("%s", err)
		os.Exit(1)
	}

	proxyServer := proxy.NewProxyServer(opts)

	opts.ServiceAccountToken = readServiceAccountToken()
	log.Printf("Registering Handlers....")
	proxyServer.RegisterRequestHandlers(auth.NewHandlers(opts))
	proxyServer.RegisterRequestHandlers(cl.NewHandlers(opts))

	var h http.Handler = proxyServer
	if opts.RequestLogging {
		h = proxy.LoggingHandler(os.Stdout, h, true)
	}
	s := &proxy.Server{
		Handler: h,
		Opts:    opts,
	}
	s.ListenAndServe()
}

func readServiceAccountToken() string {
	log.Debug("Reading ServiceAccount token...")
	var data []byte
	var err error
	if data, err = ioutil.ReadFile(serviceAccountTokenPath); err != nil || len(data) == 0 {
		log.Fatalf("Unable to load serviceaccount token from %q", serviceAccountTokenPath)
	}
	return strings.TrimSpace(string(data))
}
