package authorization

import (
	"net/http"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	clients "github.com/openshift/elasticsearch-proxy/pkg/clients"
	"github.com/bitly/go-simplejson"
	"github.com/openshift/elasticsearch-proxy/pkg/config"
	handlers "github.com/openshift/elasticsearch-proxy/pkg/handlers"
)

type osClientFake struct {
	userName string
	groups []string
}

func (client *osClientFake) Get(path, token string) (*simplejson.Json, error){
	json := simplejson.New()
	return json, nil
}

func (client *osClientFake) TokenReview(token string) (*clients.TokenReview, error){
	json := simplejson.New()
	json.SetPath([]string{"status","user","username"}, client.userName)
	json.SetPath([]string{"status","user","groups"}, client.groups)
	return &clients.TokenReview{json}, nil
}

func (client *osClientFake) SubjectAccessReview(user, namespace, verb, resource, resourceAPIGroup string) (bool, error){
	return false, nil
}

var _ = Describe("Authorization handler", func() {

	var (
		request *http.Request
	)
	
	BeforeEach(func() {
		request = &http.Request{Header: http.Header{}}
	})
	
	Describe("#Process", func(){
		var (
			context *handlers.RequestContext
			handler *authorizationHandler
			err error
		)

		BeforeEach(func(){
			handler = &authorizationHandler{
				&config.Options{},
				&osClientFake{
					userName: "foo",
					groups: []string{"xyz", "abc"},
				},
			}
			request.Header.Add(headerAuthorization, "Bearer aksadfjfasdf")
			context = &handlers.RequestContext{}
			request, err = handler.Process(request, context)
			Expect(err).To(BeNil())
		})

		It("should add the username to the request headers", func(){
			Expect(request.Header.Get(headerForwardedUser)).Should(Not(BeEmpty()))
		})
		It("should add the roles to the request headers", func(){
			roles := request.Header[headerForwardedRole]
			Expect(len(roles)).Should(Equal(2))
		})
		It("should add the namespaces to the request headers", func(){
			namespaces := request.Header[headerForwardedNamespace]
			Expect(len(namespaces)).Should(Equal(2))
		})
		It("should add the namespace uids to the request headers", func(){
			uids := request.Header[headerForwardedNamespaceUID]
			Expect(len(uids)).Should(Equal(2))
		})
	})

	Describe("#sanitizeRequest", func() {

		BeforeEach(func() {
			request.Header.Add(headerAuthorization, "someValue")
			request.Header.Add("someotherkey", "someotherValue")
		})

		It("should remove the authorization header", func() {
			sanitizeHeaders(request)
			Expect(request.Header.Get(headerAuthorization)).Should(BeEmpty())
		})
		It("should not remove other headers", func() {
			sanitizeHeaders(request)
			Expect(request.Header.Get("someotherkey")).Should(Not(BeEmpty()))
		})

	})

	Describe("#getBearerTokenFrom", func() {

		Context("is a non-bearer token", func() {

			It("should return nothing", func() {
				request.Header.Add(headerAuthorization, "Basic aksadfjfasdf")
				Expect(getBearerTokenFrom(request)).Should(BeEmpty())
			})

		})

		Context("is bearer token", func() {

			It("should return the token", func() {
				request.Header.Add(headerAuthorization, "Bearer aksadfjfasdf")
				Expect(getBearerTokenFrom(request)).Should(Not(BeEmpty()))
			})

			It("should return the token regardless of case", func() {
				request.Header.Add(headerAuthorization, "BeARer aksadfjfasdf")
				Expect(getBearerTokenFrom(request)).Should(Not(BeEmpty()))
			})

		})
	})

})
