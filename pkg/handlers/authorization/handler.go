package authorization

import (
	"net/http"
	"strings"

	"github.com/bitly/go-simplejson"
	log "github.com/openshift/elasticsearch-proxy/pkg/logging"


	clients "github.com/openshift/elasticsearch-proxy/pkg/clients"
	"github.com/openshift/elasticsearch-proxy/pkg/config"
	handlers "github.com/openshift/elasticsearch-proxy/pkg/handlers"
)

const (
	headerAuthorization         = "Authorization"
	headerForwardedUser         = "X-Forwarded-User"
	headerForwardedRole         = "X-Forwarded-Role"
	headerForwardedNamespace    = "X-Forwarded-Namespace"
	headerForwardedNamespaceUID = "X-Forwarded-NamespaceUID"
	serviceAccountTokenPath     = "/var/run/secrets/kubernetes.io/serviceaccount/token"
)

type authorizationHandler struct {
	config   *config.Options
	osClient clients.OpenShiftClient
}

//NewHandlers is the initializer for this handler
func NewHandlers(opts *config.Options) (_ []handlers.RequestHandler) {
	osClient, err := clients.NewOpenShiftClient()
	if err != nil {
		log.Fatalf("Error constructing OpenShiftClient %v", err)
	}
	return []handlers.RequestHandler{
		&authorizationHandler{
			opts,
			osClient,
			// defaultbackendRoleConfig,
		},
	}
}

//Name returns the name of this hadler
func (auth *authorizationHandler) Name() string {
	return "authorization"
}

//Process this requestion using the given context
func (auth *authorizationHandler) Process(req *http.Request, context *handlers.RequestContext) (*http.Request, error) {
	log.Tracef("Processing request in handler %q", auth.Name())
	context.Token = getBearerTokenFrom(req)
	if context.Token == "" {
		log.Debugf("Skipping %s as there is no bearer token present", auth.Name())
		return req, nil
	}
	sanitizeHeaders(req)
	auth.fillContext(context)

	req.Header.Set(headerForwardedUser, context.UserName)

	for _, role := range context.Roles {
		req.Header.Add(headerForwardedRole, role)
	}
	for _, ns := range context.Namespaces {
		req.Header.Add(headerForwardedNamespace, ns.Name)
		req.Header.Add(headerForwardedNamespaceUID, ns.UID)
	}
	return req, nil
}

func (auth *authorizationHandler) fillContext(context *handlers.RequestContext) error {
	json, err := auth.osClient.TokenReview(context.Token)
	if err != nil {
		log.Errorf("Error fetching user info %v", err)
		return err
	}
	context.UserName = json.UserName()
	log.Debugf("User is %q", json.UserName())
	auth.fetchRoles(context)
	auth.fetchNamespaces(context)
	return nil
}

func (auth *authorizationHandler) fetchRoles(context *handlers.RequestContext) []string {
	log.Debug("Determining roles...")
	for name, sar := range auth.config.AuthBackEndRoles {
		if allowed, err := auth.osClient.SubjectAccessReview(context.UserName, sar.Namespace, sar.Verb, sar.Resource, sar.ResourceAPIGroup); err == nil {
			log.Debugf("%q for %q SAR: %v", context.UserName, name, allowed)
			if allowed {
				context.Roles = append(context.Roles, name)
			}
		} else {
			log.Errorf("Unable to evaluate %s SAR for user %s: %v", name, context.UserName, err)
		}
	}
	return context.Roles
}

func (auth *authorizationHandler) fetchNamespaces(context *handlers.RequestContext) []handlers.Namespace {
	log.Debugf("Fetching namespaces for user %q", context.UserName)

	var json *simplejson.Json
	var err error
	if json, err = auth.osClient.Get("apis/project.openshift.io/v1/projects", context.Token); err != nil {
		log.Errorf("There was an error fetching namespaces: %v", err)
	} else {
		if items, ok := json.CheckGet("items"); ok {
			total := len(items.MustArray())
			for i := 0; i < total; i++ {
				//check for missing?
				var name, uid string
				if value := items.GetIndex(i).GetPath("metadata", "name"); value.Interface() != nil {
					name = value.MustString()
				}
				if value := items.GetIndex(i).GetPath("metadata", "uid"); value.Interface() != nil {
					uid = value.MustString()
				}
				context.Namespaces = append(context.Namespaces, handlers.Namespace{Name: name, UID: uid})
			}
		}
	}
	return context.Namespaces
}

func sanitizeHeaders(req *http.Request) {
	req.Header.Del(headerAuthorization)
}

func getBearerTokenFrom(req *http.Request) string {
	parts := strings.SplitN(req.Header.Get(headerAuthorization), " ", 2)
	if len(parts) > 0 && strings.ToLower(parts[0]) == "bearer" {
		return parts[1]
	}
	log.Trace("No bearer token found on request. Returning ''")
	return ""
}
