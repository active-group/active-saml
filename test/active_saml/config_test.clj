(ns active-saml.config-test
  (:require [active.clojure.config :as active-config]
            [active-saml.config :as saml-config]
            [clojure.test :as t]))

(def empty-config {})

(def empty-config-normalized
  {:saml
   {:service-app-name          "",
    :service-metadata-endpoint "",
    :service-acs-endpoint      "",
    :service-sls-endpoint      "",
    :service-public-key-file   "",
    :service-private-key-file  "",
    :identity-providers        []}})

(def example-config-normalized
  {:saml
   {:service-metadata-endpoint "/saml/metadata"
    :service-acs-endpoint      "/saml/login"
    :service-sls-endpoint      "/saml/logout"
    :service-app-name          ""
    :service-public-key-file   ""
    :service-private-key-file  ""
    :identity-providers
    [{:idp-label       "label"
      :idp-sso-service "sso"
      :idp-slo-service "ssl"
      :idp-check-ssl?  false
      :idp-cert-file   ""}]}})

(def example-config (saml-config/make-config example-config-normalized))

(t/deftest normalize-schema-test
  (t/testing "an empty map is a valid configuration"
    (t/is (= empty-config-normalized
             (active-config/normalize&check-config-object saml-config/schema [] empty-config))))
  (t/testing "example config is valid"
    (t/is (= example-config-normalized
             (active-config/normalize&check-config-object saml-config/schema [] example-config-normalized)))))
