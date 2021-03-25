(ns active-saml.saml
  "Namespace that makes available functions that handles SAML communication."
  (:require [active.clojure.config :as config]
            [active.clojure.record :refer [define-record-type]]
            [active.clojure.logger.event :as log]

            [active-saml.config :as saml-config]

            [clojure.string :as string]
            [saml20-clj.core :as saml]
            [saml20-clj.coerce :as coerce]
            [saml20-clj.crypto :as crypto]
            [saml20-clj.encode-decode :as saml-encode]
            [java-time :as t]))

(defn tagged-uuid
  [tag]
  (str (java.util.UUID/nameUUIDFromBytes (.getBytes ^String tag))
       "|" (java.util.UUID/randomUUID)))

(defn tagged?
  [uuid tag]
  (= (str (java.util.UUID/nameUUIDFromBytes (.getBytes ^String tag)))
     (first (string/split uuid #"\|"))))

(defn get-key-pair
  [public-key-file private-key-file]
  (try
    [(slurp public-key-file)
     (when private-key-file
       (slurp private-key-file))]
    (catch Exception e
      (log/log-event! :error (log/log-msg "Error reading key pair" (pr-str [public-key-file private-key-file]) (pr-str e)))
      nil)))

(defn make-cert
  ([public-key-file]
   (make-cert public-key-file nil))
  ([public-key-file private-key-file]
   (try
     (coerce/->X509Certificate (coerce/->Credential (get-key-pair public-key-file private-key-file)))
     (catch Exception e
       (log/log-event! :error (log/log-msg "Error building certificate" (pr-str e)))
       nil))))

(defn make-metadata!
  [app-name acs-url slo-url public-key-file private-key-file]
  (-> {:sp-cert (make-cert public-key-file private-key-file)}
      (merge {:app-name app-name
              :acs-url  acs-url
              :slo-url  slo-url})
      saml/metadata))

(defn config->metadata!
  [config]
  (make-metadata!
   (config/access config saml-config/service-app-name-setting saml-config/section)
   (config/access config saml-config/service-acs-endpoint-setting saml-config/section)
   (config/access config saml-config/service-sls-endpoint-setting saml-config/section)
   (config/access config saml-config/service-public-key-file-setting saml-config/section)
   (config/access config saml-config/service-private-key-file-setting saml-config/section)))

(define-record-type login-request
  make-login-request
  login-request?
  [label login-request-label
   form-action login-request-form-action
   relay-state login-request-relay-state
   saml-request login-request-saml-request])

(defn make-login-request!
  [issuer acs-url public-key-file private-key-file label idp-url next]
  (let [saml-request (saml/request
                      {:sp-name     issuer
                       :acs-url     acs-url
                       :idp-url     idp-url
                       :issuer      issuer
                       :credential  (get-key-pair public-key-file private-key-file)
                       :request-id  (tagged-uuid idp-url)})
        saml-request-str (if (string? saml-request)
                           saml-request
                           (coerce/->xml-string saml-request))
        req-b64          (saml-encode/str->base64 saml-request-str)]
    (make-login-request label idp-url next req-b64)))

(defn config+next->login-requests!
  [config next]
  (map #(make-login-request!
         (config/access config saml-config/service-app-name-setting saml-config/section)
         (config/access config saml-config/service-acs-endpoint-setting saml-config/section)
         (config/access config saml-config/service-public-key-file-setting saml-config/section)
         (config/access config saml-config/service-private-key-file-setting saml-config/section)
         %1 %2 next)
       (config/access config saml-config/idp-label saml-config/section saml-config/idps-section)
       (config/access config saml-config/idp-sso-service-setting saml-config/section saml-config/idps-section)))

(define-record-type login-response
  make-login-response
  login-response?
  [name-id login-response-name-id
   groups login-response-groups
   assertion-maps login-response-assertion-maps
   next login-response-next
   idp login-response-idp])

(define-record-type idp
  make-idp
  idp?
  [label idp-label
   sso-service idp-sso-service
   slo-service idp-slo-service
   check-ssl? idp-check-ssl?
   cert idp-cert-file])

(defn idp-matches?
  [idp in-response-to]
  (fn [idp] (when (tagged? (idp-sso-service idp) in-response-to) idp)))

(defn config->idps
  [config]
  (map make-idp
       (config/access config saml-config/idp-label saml-config/section saml-config/idps-section)
       (config/access config saml-config/idp-sso-service-setting saml-config/section saml-config/idps-section)
       (config/access config saml-config/idp-slo-service-setting saml-config/section saml-config/idps-section)
       (config/access config saml-config/idp-check-ssl-setting saml-config/section saml-config/idps-section)
       (config/access config saml-config/idp-cert-file-setting saml-config/section saml-config/idps-section)))

(defn maybe-validate
  [response check? make-cert-fn sp-private-key]
  (if check?
    (saml/validate response (make-cert-fn) sp-private-key)
    response))

(def relevant-groups-key "eduPersonAffiliation")

(defn config+request->login-response!
  [config req]
  (let [idps (config->idps config)
        sp-private-key
        (try
          (slurp (config/access config saml-config/service-private-key-file-setting saml-config/section))
          (catch Exception e
            (log/log-event! :error (log/log-msg "Error reading private key" (config/access config saml-config/service-private-key-file-setting saml-config/section) (pr-str e)))
            nil))
        [assertions idp]
        (some #(try
                 (let [assertions (-> req
                                      (get-in [:params "SAMLResponse"])
                                      saml-encode/base64->str
                                      saml/->Response
                                      (maybe-validate (idp-check-ssl? %) (fn [] (make-cert (idp-cert-file %))) sp-private-key)
                                      saml/assertions)]
                   (when (and assertions (idp-matches? idp (:in-response-to (:confirmation (first assertions)))))
                     [assertions %]))
                 (catch Exception e
                   nil))
              idps)
        next (get-in req [:params "RelayState"])
        groups (reduce (fn [res assertion]
                         (concat res (get-in assertion [:attrs relevant-groups-key])))
                       []
                       assertions)
        name-id (get-in (first assertions) [:name-id :value])]
    (make-login-response name-id groups assertions next idp)))

(defn- format-instant
  "Converts a date-time to a SAML 2.0 time string."
  [instant]
  (t/format (t/format "YYYY-MM-dd'T'HH:mm:ss'Z'" (t/offset-date-time instant (t/zone-offset 0)))))

(defn logout-request!
  "Return XML elements that represent a SAML 2.0 logout request."
  ^org.w3c.dom.Element [{:keys [ ;; e.g. something like a UUID. Random UUID will be used if no other ID is provided
                                request-id
                                ;; e.g. http://idp.example.com/SSOService.php
                                slo-url
                                ;; e.g. http://sp.example.com/demo1/metadata.php
                                issuer
                                ;; the token to logout with
                                name-id
                                ;; If present, we can sign the request
                                credential
                                instant]
                         :or   {request-id (str "id" (java.util.UUID/randomUUID))
                                instant (t/instant)}}]
  (let [request (coerce/->Element
                 (coerce/->xml-string
                  [:samlp:LogoutRequest
                   {:xmlns:samlp                 "urn:oasis:names:tc:SAML:2.0:protocol"
                    :xmlns:saml                  "urn:oasis:names:tc:SAML:2.0:assertion"
                    :ID                          request-id
                    :Version                     "2.0"
                    :IssueInstant                (format-instant instant)
                    :Destination                 slo-url}
                   [:saml:Issuer
                    issuer]
                   [:samlp:NameID {:SPNameQualifier issuer :Format "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"}
                    name-id]]))]
    (if-not credential
      request
      (or (crypto/sign request credential)
          (throw (ex-info "Failed to sign request" {:request request}))))))

(define-record-type LogoutRequest
  make-logout-request
  logout-request?
  [form-action logout-request-form-action
   saml-request logout-request-saml-request])

(defn make-logout-request!
  [issuer slo-url name-id public-key-file private-key-file]
  (let [saml-request (logout-request!
                      {:issuer     issuer
                       :slo-url    slo-url
                       :name-id    name-id
                       :credential (get-key-pair public-key-file private-key-file)
                       :request-id (tagged-uuid slo-url)})
        saml-request-str (if (string? saml-request)
                           saml-request
                           (coerce/->xml-string saml-request))
        req-b64          (saml-encode/str->base64 saml-request-str)]
    (make-logout-request slo-url req-b64)))

(defn config+login-response->logout-request!
  [config login-response]
  (make-logout-request!
   (config/access config saml-config/service-app-name-setting saml-config/section)
   (idp-slo-service (login-response-idp login-response))
   (login-response-name-id login-response)
   (config/access config saml-config/service-public-key-file-setting saml-config/section)
   (config/access config saml-config/service-private-key-file-setting saml-config/section)))

(define-record-type LogoutResponse
  make-logout-response
  logout-response?
  [success logout-response-success
   next logout-response-next
   request logout-response-request])

(defn request->logout-response!
  [request]
  (make-logout-response true ;; FIXME: Could look at actual response here
                        (get-in request [:header "referer"] "../")
                        request))
