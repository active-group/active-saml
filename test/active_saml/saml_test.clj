(ns active-saml.saml-test
  (:require [clojure.test :as t]

            [active-saml.config :as saml-config]
            [active-saml.saml :as saml]))

(t/deftest make-login-request!-test
  (let [login-request (saml/make-login-request! "issuer"
                                                "acs"
                                                "public"
                                                "private"
                                                "label"
                                                "sso"
                                                "next")]
    (t/is (= "label" (saml/login-request-label login-request)))
    (t/is (= "sso" (saml/login-request-form-action login-request)))
    (t/is (= "next" (saml/login-request-relay-state login-request)))
    (t/is (some? (saml/login-request-saml-request login-request)))))

(t/deftest config+next->login-requests!-test
  (let [config (-> {:saml {:service-metadata-endpoint "/saml/metadata"
                           :service-acs-endpoint      "/saml/login"
                           :service-sls-endpoint      "/saml/logout"
                           :service-app-name          "Service"
                           :service-public-key-file   ""
                           :service-private-key-file  ""
                           :identity-providers        [{:idp-label       "label"
                                                        :idp-sso-service "sso"
                                                        :idp-slo-service "ssl"
                                                        :idp-check-ssl?  false
                                                        :idp-cert-file   ""}]}})
        next*  "next"
        res    (saml/config+next->login-requests! (saml-config/make-config config) next*)
        [login-request & _]
        res]
    (t/testing "with only one configured idp"
      (t/is (= 1 (count res)))
      (t/is (= "label" (saml/login-request-label login-request)))
      (t/is (= "sso" (saml/login-request-form-action login-request)))
      (t/is (= "next" (saml/login-request-relay-state login-request)))
      (t/is (some? (saml/login-request-saml-request login-request))))

    (t/testing "with multiple idps, respects configuration order"
      (let [config (update-in config
                              [:saml :identity-providers]
                              conj
                              {:idp-label       "other label"
                               :idp-sso-service "other sso"
                               :idp-slo-service "other ssl"
                               :idp-check-ssl?  false
                               :idp-cert-file   ""})
            res    (saml/config+next->login-requests! (saml-config/make-config config) next*)
            [fst snd & _] res]
        (t/is (= 2 (count res)))

        (t/is (= "label" (saml/login-request-label fst)))
        (t/is (= "sso" (saml/login-request-form-action fst)))
        (t/is (= "next" (saml/login-request-relay-state fst)))
        (t/is (some? (saml/login-request-saml-request fst)))

        (t/is (= "other label" (saml/login-request-label snd)))
        (t/is (= "other sso" (saml/login-request-form-action snd)))
        (t/is (= "next" (saml/login-request-relay-state snd)))
        (t/is (some? (saml/login-request-saml-request snd)))))))

(t/deftest config->idps-test
  (let [config (-> {:saml {:identity-providers
                           [{:idp-label       "label"
                             :idp-sso-service "sso"
                             :idp-slo-service "sls"
                             :idp-check-ssl?  false
                             :idp-cert-file   ""}
                            {:idp-label       "other label"
                             :idp-sso-service "other sso"
                             :idp-slo-service "other sls"
                             :idp-check-ssl?  false
                             :idp-cert-file   ""}]}}
                   saml-config/make-config)]
    (t/is (= [(saml/make-idp "label" "sso" "sls" false "")
              (saml/make-idp "other label" "other sso" "other sls" false "")]
             (saml/config->idps config)))))
