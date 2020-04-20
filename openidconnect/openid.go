package openidconnect

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

//_______________________________________________UNUSED__________________________________________________
// EndSessionEndpoint                         string
// CheckSessionIFrame                         string
// ACRValuesSupported                         []string `json:"acr_values_supported"`
// IDTokenEncryptionAlgValues                 []string `json:"id_token_encryption_alg_values_supported"`
// IDTokenEncryptionEncValues                 []string `json:"id_token_encryption_enc_values_supported"`
// UserInfoSigningAlgValues                   []string `json:"userinfo_signing_alg_values_supported"`
// UserInfoEncryptionAlgValues                []string `json:"userinfo_encryption_alg_values_supported"`
// UserInfoEncryptionEncValues                []string `json:"userinfo_encryption_enc_values_supported"`
// ReqObjSigningAlgValues                     []string `json:"request_object_signing_alg_values_supported"`
// ReqObjEncryptionAlgValues                  []string `json:"request_object_encryption_alg_values_supported"`
// ReqObjEncryptionEncValues                  []string `json:"request_object_encryption_enc_values_supported"`
// DisplayValuesSupported                     []string `json:"display_values_supported"`
// ClaimTypesSupported                        []string `json:"claim_types_supported"`
// ClaimsLocalsSupported                      []string `json:"claims_locales_supported"`
// UILocalsSupported                          []string `json:"ui_locales_supported"`
// RequestParameterSupported                  bool     `json:"request_parameter_supported"`
// RequestURIParamaterSupported               bool     `json:"request_uri_parameter_supported"`
// RequireRequestURIRegistration              bool     `json:"require_request_uri_registration"`
// ServiceDocs                                string   `json:"service_documentation"`
// Policy                                     string   `json:"op_policy_uri"`
// TermsOfService                             string   `json:"op_tos_uri"`
//_______________________________________________________________________________________________________

//OpenIDDiscoveryConfig represents the publically available OpenID Connect Provider Configuration
type OpenIDDiscoveryConfig struct {
	Issuer                                     string   `json:"issuer"`
	AuthEndpoint                               string   `json:"authorization_endpoint"`
	TokenEndpoint                              string   `json:"token_endpoint"`
	UserInfoEndpoint                           string   `json:"userinfo_endpoint"`
	RegistrationEndpoint                       string   `json:"registration_endpoint"`
	KeysEndpoint                               string   `json:"jwks_uri"`
	ClaimsParameterSupported                   bool     `json:"claims_parameter_supported"`
	ScopesSupported                            []string `json:"scopes_supported"`
	ResponseTypesSupported                     []string `json:"response_types_supported"`
	ResponseModesSupported                     []string `json:"response_modes_supported"`
	GrantTypesSupported                        []string `json:"grant_types_supported"`
	SubjectTypesSupported                      []string `json:"subject_types_supported"`
	IDTokenSigningAlgValues                    []string `json:"id_token_signing_alg_values_supported"`
	TokenEndpointAuthMethodsSupported          []string `json:"token_endpoint_auth_methods_supported"`
	TokenEndpointAuthSigningAlgValuesSupported []string `json:"token_endpoint_auth_signing_alg_values_supported"`
	ClaimsSupported                            []string `json:"claims_supported"`
}

//OpenIDProvider represents an identity provider compliant w/ OpenID Connect
type OpenIDProvider struct {
	IssuerURL string
	KeysURL   string
}

//GetDiscoveryConfig returns the OpenID Configuration of an OpenID Connect Provider
func (idp *OpenIDProvider) GetDiscoveryConfig() (*OpenIDDiscoveryConfig, error) {
	//send a request to get the struct
	resp, err := http.Get(idp.IssuerURL + "/.well-know/webfinder")
	if err != nil {
		return nil, fmt.Errorf("[ERROR] Could not fetch OpenID Configuration: %s", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("[ERROR] Bad response from discovery endpoint HTTP: %d", resp.StatusCode)
	}
	//read the bytes that came back
	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("[ERROR] Could not read body of discovery endpoint response: %s", err)
	}
	defer resp.Body.Close()
	//unmarshall onto the struct
	var discoveryConfig OpenIDDiscoveryConfig
	err = json.Unmarshal(respBytes, &discoveryConfig)
	if err != nil {
		return nil, fmt.Errorf("[ERROR] Bad type / could not parse OpenID configuration: %s", err)
	}

	return &discoveryConfig, nil
}

//OpenIDConfigDiscovery is an HTTP Req. Handler that exposes the OpenIDConfigDiscovery struct
func (idp *OpenIDProvider) OpenIDConfigDiscovery(w http.ResponseWriter, r *http.Request) {
	resp, err := json.Marshal(
		OpenIDDiscoveryConfig{
			Issuer:                            idp.IssuerURL,
			AuthEndpoint:                      idp.IssuerURL + "/auth",
			TokenEndpoint:                     idp.IssuerURL + "/auth/token",
			UserInfoEndpoint:                  idp.IssuerURL + "/auth/userinfo",
			KeysEndpoint:                      idp.IssuerURL + "/auth/keys",
			ScopesSupported:                   []string{"openid"},
			ResponseTypesSupported:            []string{"code", "id_token", "token id_token"},
			ResponseModesSupported:            []string{"query", "fragment"},
			GrantTypesSupported:               []string{"refresh_token"},
			SubjectTypesSupported:             []string{"pairwise"},
			IDTokenSigningAlgValues:           []string{"RS512"},
			TokenEndpointAuthMethodsSupported: []string{"client_secret_basic"},
			TokenEndpointAuthSigningAlgValuesSupported: []string{"RS512"},
			ClaimsSupported: []string{
				"aud",
				"exp",
				"jti",
				"iat",
				"iss",
				"sub",
				"grps",
			},
		})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, string("[ERROR]"))
		return
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, string(resp))
	return
}
