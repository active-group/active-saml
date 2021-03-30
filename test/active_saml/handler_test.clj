(ns active-saml.handler-test
  (:require [active.clojure.monad :as monad]
            [clojure.string :as string]
            [clojure.test :as t]
            [ring.mock.request :as mock]
            [ring.middleware.params :as ring-params]

            [active-saml.config :as saml-config]
            [active-saml.saml :as saml]
            [active-saml.handler :as handler]
            [active-saml.config-test :as config-test]))

(def empty-test-config
  (saml-config/make-config {:saml {:service-app-name           "Testservice"
                                   :service-saml-assertion-key :group}}))

(def test-config-with-idp
  (saml-config/make-config
   {:saml {:service-metadata-endpoint  "/saml/metadata"
           :service-acs-endpoint       "/saml/login"
           :service-sls-endpoint       "/saml/logout"
           :service-app-name           "Service"
           :service-public-key-file    ""
           :service-private-key-file   ""
           :service-saml-assertion-key :group
           :identity-providers         [{:idp-label       "label"
                                         :idp-sso-service "sso"
                                         :idp-slo-service "ssl"
                                         :idp-check-ssl?  false
                                         :idp-cert-file   ""}]}}))

(t/deftest request-next-test
  (t/is (= "next" (handler/request-next {:query-params {"next" "next"}})))
  (t/is (= "./" (handler/request-next {}))))

(def mock-no-idp-available-response "no-idp-available")
(def mock-login-page identity)

(defn mock-login-response-callback
  [login-response logout-request]
  {:login-reponse login-response
   :logout-request logout-request})

(t/deftest handle-get-login-test
  (let [prog (handler/handle-get-login mock-no-idp-available-response
                                       mock-login-page)]
    (t/testing "returns no-idp-available-response when no idp is configured."
      (t/is (= mock-no-idp-available-response
               ((handler/run-session* empty-test-config prog) ::request))))
    (t/testing "returns the supplied responses and requests"
      (let [resp ((handler/run-session* test-config-with-idp prog)
                  (mock/request :get "/saml/login"))]
        (t/is (= 1 (count resp)))
        (t/is (= "label" (saml/login-request-label (first resp))))
        (t/is (= "sso" (saml/login-request-form-action (first resp))))
        (t/is (= "./" (saml/login-request-relay-state (first resp))))))))

(t/deftest routes-test
  (let [handler (fn [config]
                  (-> (handler/routes config
                                      mock-no-idp-available-response
                                      (fn [login-requests]
                                        {:status 200
                                         :body   login-requests})
                                      (constantly nil)
                                      (constantly nil))
                      ring-params/wrap-params))]

    (t/testing "GET"
      (t/testing "/metadata"
        (let [{:keys [status headers body]}
              ((handler empty-test-config)
               (mock/request :get "/saml/metadata"))]
          (t/is (= 200 status))
          (t/is (= {"Content-Type" "application/xml"} headers))
          (t/is (= (saml/config->metadata! empty-test-config) body))))

      (t/testing "/login"
        (t/testing "without any configured idps"
          (let [req (mock/request :get "/saml/login")
                {:keys [status headers body]}
                ((handler empty-test-config) req)]
            (t/is (= 200 status))
            (t/is (= body mock-no-idp-available-response))))

        (t/testing "without configured idps"
          (let [req                  (mock/request :get "/saml/login")
                {:keys [status headers body]}
                ((handler test-config-with-idp) req)
                [login-response & _] body]
            (t/is (= 200 status))
            (t/is (= "label" (saml/login-request-label login-response)))
            (t/is (= "sso" (saml/login-request-form-action login-response)))
            (t/is (= "./" (saml/login-request-relay-state login-response)))))))
    (t/testing "POST"
      (t/testing "/login"
        ;; TODO
        ))
    (t/testing "ANY"
      (t/testing "/logout"
        ;; TODO
        ))))
