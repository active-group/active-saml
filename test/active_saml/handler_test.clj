(ns active-saml.handler-test
  (:require [active.clojure.monad :as monad]
            [clojure.string :as string]
            [clojure.test :as t]
            [ring.mock.request :as mock]
            [ring.middleware.params :as ring-params]
            [active-saml.saml :as saml]
            [active-saml.handler :as handler]
            [active-saml.config-test :as config-test]))

(def test-config config-test/example-config)

(t/deftest routes-test
  (let [handler (-> (handler/routes test-config (constantly nil) (constantly nil) (constantly nil))
                    ring-params/wrap-params)]
    (t/testing "/saml"
      (t/testing "/metadata"
        (t/testing "GET"
          (let [{:keys [status headers body]} (handler (mock/request :get "/saml/metadata"))]
            (t/is (= 200 status))
            (t/is (= {"Content-Type" "application/xml"} headers))
            (t/is (= (saml/config->metadata! test-config) body)))))

      (t/testing "/login"
        (t/testing "POST"
          (let [{:keys [status headers body]} (handler (-> (mock/request :post "/saml/login")
                                                           (mock/query-string "")))]))))))
