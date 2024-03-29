(ns active-saml.config
  "Configuration for the authentication facilities of a SAML service provider."
  (:require [active.clojure.config :as config]))

;; SAML configuration

;; IdP
(def idp-label
  (config/setting
   :idp-label
   "The label of the button for login."
   config/string-range))

(def idp-sso-service-setting
  (config/setting
   :idp-sso-service
   "The endpoint of the IdPs Single Sign On service."
   config/string-range))

(def idp-slo-service-setting
  (config/setting
   :idp-slo-service
   "The endpoint of the IdPs Single Log Out service."
   config/string-range))

(def idp-cert-file-setting
  (config/setting
   :idp-cert-file
   "The certificate file of the idp needed for validation."
   config/string-range))

(def idp-check-ssl-setting
  (config/setting
   :idp-check-ssl?
   "Check encryption/signature on IDP responses."
   (config/boolean-range false)))

(def service-public-key-file-setting
  (config/setting
   :service-public-key-file
   "Path to the public key file used for the SAML communication."
   config/string-range))

(def service-private-key-file-setting
  (config/setting
   :service-private-key-file
   "Path to the private key file used for the SAML communication."
   config/string-range))

;; Service
(def service-app-name-setting
  (config/setting
   :service-app-name
   "The app name that the service identifies as to the SAML IdP."
   config/string-range))

(def service-acs-endpoint-setting
  (config/setting
   :service-acs-endpoint
   "An URL that points to this application's assertion consumer serivce."
   config/string-range))

(def service-sls-endpoint-setting
  (config/setting
   :service-sls-endpoint
   "An URL that points to this application's single logout service endpoint."
   config/string-range))

(def service-metadata-endpoint-setting
  (config/setting
   :service-metadata-endpoint
   "An URL that points to this application's metadata endpoint."
   config/string-range))

(def service-saml-assertion-key
  (config/setting
   :service-saml-assertion-key
   "The key under which groups of interesting for this service are stored in the saml assertions."
   (config/optional-default-range (config/any-range config/string-range config/keyword-range) "Role")))

(def idp-schema
  (config/schema "SAML configuration schema."
                 idp-label
                 idp-sso-service-setting
                 idp-slo-service-setting
                 idp-check-ssl-setting
                 idp-cert-file-setting))

(def idps-section
  (config/section :identity-providers
                  (config/sequence-schema "Sequence of SAML configurations.
The order matches the order in which each configuration is tried when
interacting with the IdP."
                                          idp-schema)))

(def section
  (config/section
   :saml
   (config/schema "Configuration schema for SAML"
                  service-app-name-setting
                  service-metadata-endpoint-setting
                  service-acs-endpoint-setting
                  service-sls-endpoint-setting
                  service-public-key-file-setting
                  service-private-key-file-setting
                  service-saml-assertion-key
                  idps-section)))

(def schema
  (config/schema "SAML config" section))

(defn make-config
  [config]
  (config/make-configuration
   schema
   [] config))

(defn get-config
  [config]
  (make-config {:saml (config/access config section)}))
