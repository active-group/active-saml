(ns active-saml.commands
  "Monadic commands for SAML communication."
  (:require [active.clojure.monad :as monad]
            [active.clojure.record :refer [define-record-type]]
            [active.clojure.logger.event :as log]
            [active-saml.saml :as saml]))


(define-record-type GetMetadata
  get-metadata
  get-metadata?
  [])

(define-record-type GetLoginRequests
  get-login-requests
  get-login-requests?
  [next get-login-requests-next])

(define-record-type GetLoginResponse
  get-login-response
  get-login-response?
  [])

(def get-request
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
      (let [saml-config     (::saml-config env)]
        [(saml/config+request->login-response! saml-config request)
         state])

      :else
      monad/unknown-command)))

(defn command-config
  [saml-config request]
  (monad/make-monad-command-config run
                                   {::saml-config saml-config}
                                   {::request request}))

(defn run-session
  [saml-config request m]
  (monad/run-monadic-swiss-army
   (command-config saml-config request) m))
