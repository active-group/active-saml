# active-saml

A library for SAML auth that can easily hooked into a compjure app.

[![Clojars Project](https://img.shields.io/clojars/v/de.active-group/active-saml.svg)](https://clojars.org/de.active-group/active-saml)

## Usage
So setup the required endpoints, hook to following into your compjure
application. In this somewhat longer example, we use
[Hiccup](https://github.com/weavejester/hiccup) to generate HTML output. Feel
free to respond to the requests however you like.

```clojure
(ns your.app
  (:require [compojure.core :as compojure]
            [hiccup.page :as hiccup]

            ;; ...

            [active.saml.config :as saml-config]
            [active-saml.saml :as saml]
            [active-saml.handler :as saml-handler]))

(def config-map
  {:saml
   {:service-app-name          "My Service"
    :service-metadata-endpoint "https://localhost:1234/metadata"
    :service-acs-endpoint      "https://localhost:1234/login"
    :service-sls-endpoint      "https://localhost:1234/logout"
    :service-public-key-file   "path/to/public/key"
    :service-private-key-file  "path/to/private/key"
    :identity-providers
    [{{:idp-label       "My IdP"
       :idp-sso-service "https://localhost:4321/login"
       :idp-slo-service "https://localhost:4321/logout"
       :idp-check-ssl?  false
       :idp-cert-file   "path/to/cert/file"}}]}})

(def config (saml-config/make-config config-map))

(def no-idp-available-response
  "<h1>No idp available</h1>")

(defn login-request->login-button
  "Generate a html button for hiccup, based on a `login-request`."
  [login-request]
  [:form {:method "post"
          :action (saml/login-request-form-action login-request)
          :id     "login-form"}
   [:input {:type  "hidden"
            :name  "RelayState"
            :value (saml/login-request-relay-state login-request)}]
   [:input {:type  "hidden"
            :name  "SAMLRequest"
            :value (saml/login-request-saml-request login-request)}]
   [:button.btn.btn-success {:type "submit"} (saml/login-request-label login-request)]])

;; This should return some http response.
(defn login-page
  "Display a saml login button for each configured idp."
  [login-requests]
  {:status 200
   :body   (hiccup/html5 [:html
                        [:body
                         (map longin-request->login-button login-requests)]])})

;; This is called after a successful login at the IdP.
;; Handle your own user sessions, etc. here.
(defn login-response-callback
  [login-response logout-request]
  (let [next    (saml/login-response-next login-response)
        name-id (saml/login-response-name-id login-response)]
    ;; Do something with the response, e.g. login a user, etc.
    {:status  302
     :headers {"Location" next}
     :body    "success login"}))

;; This is called after the user logs out at the IdP.
(defn logout-response-callback
  [logout-response]
  (let [request (saml/logout-response-request logout-response)
        name-id (req->logged-in-name-id request)
        next    (saml/logout-response-next logout-response)]
    ;; Do something with the response, e.g. logout a user, etc.
    {:status 200
     :body   "successful logout"}))

(compojure/defroutes app
  ...   ; your other routes.

  (saml-handler/routes config
                       no-idp-available-response
                       login-page
                       login-response-callback
                       logout-response-callback))
```




This will create a context under `/saml`, providing the following
endpoints:

- `/saml/login` (`GET`)
- `/saml/login` (`POST`)
- `/saml/logout` (`ANY`)
- `/saml/metadata` (`GET`)
 

### Configuration
You must configure your service using a Clojure map (you are of course free
to read it from a file).
One full example of such a configuration (configuring one IdP):

```clojure
   {:saml
     {:service-app-name          "My Service"
      :service-metadata-endpoint "https://localhost:1234/metadata"
      :service-acs-endpoint      "https://localhost:1234/login"
      :service-sls-endpoint      "https://localhost:1234/logout"
      :service-public-key-file   "path/to/public/key"
      :service-private-key-file  "path/to/private/key"
      :identity-providers
      [{{:idp-label       "My IdP"
         :idp-sso-service "https://localhost:4321/login"
         :idp-slo-service "https://localhost:4321/logout"
         :idp-check-ssl?  false
         :idp-cert-file   "path/to/cert/file"}}]}}
```

#### Identity Provider
Your service may want to talk to multiple SAML Identity-Providers.
Each configuration is a map with the following keys:

- `:idp-label` (String): The label of the login button. Defaults to `""`.
- `:idp-sso-service` (String): The endpoint of the IdPs Single Sign On service.
  Defaults to `""`.
- `:idp-slo-service` (String): The endpoint of the IdPs Single Log Out service.
  Defaults to `""`.
- `:idp-cert-file` (String): Path to the certificate file the IdP needed for
    validation. Defaults to `""`.
- `:idp-check-ssl` (Boolean): Check encryption/signature on IDP responses.
  Defaults to `false`.

#### Service
Your service must define the following values in it's configuration:
- `:service-public-key-file` (String): Path to the public key file used for the
  SAML communication. Defaults to `""`.
- `:service-private-key-file` (String): Path to the private key file used for
  the SAML communication. Defaults to `""`.
- `:service-app-name` (String): The app name that the service identifies as to
    the SAML IdP. Defaults to `""`.
- `:service-acs-endpoint` (String): An URL that points to this service's
    assertion consumer serivce. Defaults to `""`.
- `:service-sls-endpoint` (String): An URL that points to this service's single
    logout service endpoint. Defaults to `""`.
- `:service-metadata-endpoint` (String): An URL that points to this service's
    metadata endpoint. Defaults to `""`.
- `:service-saml-assertion-key` (Keyword): The key under which relevant
  information for your serivce is stored in the SAML assertions response.
  No default value.
- `:identity-providers` (Vector[Ientity Provider]): A vector of Identity
  Provider configurations. Defaults to `[]`.
  
## License

Copyright © 2021 Active Group GmbH

Distributed under the Eclipse Public License either version 1.0 or (at
your option) any later version.
