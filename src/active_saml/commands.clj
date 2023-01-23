(ns active-saml.commands
  "Monadic commands for SAML communication."
  (:require [active.clojure.monad :as monad]
            [active.clojure.record :refer [define-record-type]]
            [active.clojure.logger.event :as log]
            [active-saml.saml :as saml]))


(define-record-type
  ^{:doc "Represents the intent to retrieve the service's metadata."}
  GetMetadata
  ^{:doc "Get the configured service's metadata."} get-metadata
  get-metadata?
  [])

(define-record-type
  ^{:doc "Represents the intent to generate login requests based on the
configured SAML IdPs."}
  GetLoginRequests
  ^{:doc "Get a sequence of login requests for all configured IdPs."}
  get-login-requests
  get-login-requests?
  [^{:doc "The page the user initially inteded to visit and that will be the
target of a redirect if the login was successfull."}
   next get-login-requests-next])

(define-record-type ^{:doc "Command that, when executed in the context of a
response from the IdP to a login request, extracts the payload from the request
and returns a [[active-saml.saml/LoginResponse]]."}
  GetLoginResponse
  ^{:doc "Extract the [[active-saml/LoginResponse]] from a request to the login
 route initiated by the IdP."}
  get-login-response
  get-login-response?
  [])

(define-record-type ^{:doc "Command that,  when executed in the context of a
response from the IdP to a login request, extracts the information that is later
required for a logout at that IdP and puts it in a
[[active-saml.saml/LogoutRequest]]"}
  GetLogoutRequest
  ^{:doc "Extract the logout information from an IdPs login request as a
[[active-saml.saml/LogoutRequest]]"}
  get-logout-request
  get-logout-request?
  [login-response get-logout-request-login-response])

(define-record-type ^{:doc "Command that, when executed in the context of a
response from the IdP to a logout request, extracts the payload from the request
and returns a [[active-saml.saml/LogoutResponse]]."}
  GetLogoutResponse
  ^{:doc "Extract the [[active-saml/LogoutResponse]] from a request to the
logout route initiated by the IdP."}
  get-logout-response
  get-logout-response?
  [])

(def get-request
  "Command to retrieve the currently processed request from the monad state."
  (monad/get-state-component ::request))

(defn run
  [_run-any env state m]
  (let [saml-config (::saml-config env)
        request (::request state)]
    (cond
      (get-metadata? m)
      [(saml/config->metadata! saml-config)
       state]

      (get-login-requests? m)
      [(saml/config+next->login-requests! saml-config (get-login-requests-next m))
       state]

      (get-login-response? m)
      [(saml/config+request->login-response! saml-config request)
       state]

      (get-logout-request? m)
      [(saml/config+login-response->logout-request! saml-config (get-logout-request-login-response m))
       state]

      (get-logout-response? m)
      [(saml/request->logout-response! request)
       state]

      :else
      monad/unknown-command)))

(defn- command-config
  [saml-config request]
  (monad/make-monad-command-config run
                                   {::saml-config saml-config}
                                   {::request request}))

(defn run-session
  "Run a monadic session program.

  Args:
  - `saml-config`: A [[active.clojure.config/Configuration]], e. g. the result
    of [[active-saml.config/get-config]].
  - `request`: A ring request map that is passed to the handler.
  - `m`: The (monadic) program you want to evaluate."
  [saml-config request m]
  (monad/run-monadic
   (command-config saml-config request) m))
