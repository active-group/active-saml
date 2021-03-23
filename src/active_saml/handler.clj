(ns active-saml.handler
  (:require [active.clojure.monad :as monad]
            [compojure.core :as compojure]
            [ring.util.response :as response]
            [clojure.string :as string]
            [active-saml.commands :as commands])
  (:import [java.net URLEncoder]))

(def handle-metadata
  (monad/monadic
   [metadata (commands/get-metadata)]
   (monad/return (-> (response/response metadata)
                     (response/content-type "application/xml")))))

(defn request-next
  [request]
  (or (get-in request [:query-params "next"]) "./"))

(defn handle-get-login
  [no-idp-available-response login-page]
  "Serve a login page to the user. `req` must contain a value for
  `[:query-params \"next\"]` so we can redirect the user to the requested page
  after successful authentication."
  (monad/monadic
   [request commands/get-request]
   (let [next (request-next request)])
   [login-requests (commands/get-login-requests next)]
   (if (empty? login-requests)
     (monad/return no-idp-available-response)
     (monad/monadic
      (monad/return (login-page login-requests))))))

(defn handle-login-response
  [login-response-callback]
  "Handle responses arrived here from the IdP through the client."
  (monad/monadic
    [login-response (commands/get-login-response)]
    (monad/return (login-response-callback login-response))))

#_(def handle-idp-logout
    "This endpoint is called by the IdP when a user initiates a logout.
  This happens if a user has logged out from SSO at another application."
    (monad/monadic
     [req get-request]
     (let [username (get-in req [:session :identity])])
     (logout-user! username)
     (monad/return (response/redirect (get-in req [:header "referer"] "../")))))

(defn run-session*
  "[[run-session]] specialized for use in [[routes]]."
  [config m]
  (fn [req]
    (let [[result state]
          (commands/run-session config req m)]
      result)))

(defn routes
  [config no-idp-available-response login-page login-response-callback]
  (compojure/routes
   (compojure/context
     "/saml" []
     (compojure/GET  "/login" [] (run-session* config (handle-get-login no-idp-available-response login-page)))
     (compojure/POST "/login" [] (run-session* config (handle-login-response login-response-callback)))
    ;;(compojure/ANY  "/logout" [] (run-session* config handle-logout-response))
     (compojure/GET  "/metadata" [] (run-session* config handle-metadata)))))

;; Middleware to ensure login by redirecting to login page

(defn drop-leading-slash
  "Takes a string `s` and returns `s` without any leading slashes, if any."
  [s]
  (if (string/starts-with? s "/")
    (apply str (rest s))
    s))

(defn count-subdirectories
  "Returns the number of directories accessed in the request relative to our
  root.

  Example:
      (count-subdirectories \"foo\")
      => 0

      (count-subdirectories \"foo/bar/baz\")
      => 2
  "
  [s]
  (count (filter (partial = \/) s)))

(defn nav-up
  [times s]
  (let [prefix (string/join "/" (repeat times ".."))]
    (str "./" (if (empty? prefix)
                s
                (string/join "/" [prefix s])))))

(defn redirect-to-login
  "Redirect the user to the login page. This will store the current target page
  the user wanted to access and, after a successful login, will redirect there."
  [req]
  (let [url         (drop-leading-slash (:uri req))
        ;; NOTE we have to figure out where the login page is located relative
        ;;      to the requested resource.
        root        (nav-up (count-subdirectories url) "saml/login")
        redirect-to (str root "?next=" (URLEncoder/encode url))]
    (response/redirect redirect-to)))

(defn wrap-ensure-authenticated
  "Middleware that shortcuts execution of the `handler` and redirects the user
  to the Identity provider if they are not logged in at this service.
  If there is a user with a session, add the user record to the request under
  `:logged-in-user`."
  [request->logged-in-user?]
  (fn [handler]
  (fn [req]
    (if (or (request->logged-in-user? req)
            (re-matches #"saml/login$" (or (:uri req) "")))
      (handler req)
      (redirect-to-login req)))))
