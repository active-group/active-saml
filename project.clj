(defproject de.active-group/active-saml "0.1.0-SNAPSHOT"
  :description "SAML auth."
  :url "https://github.com/active-group/active-saml"
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  :dependencies [[org.clojure/clojure "1.10.1"]
                 [de.active-group/active-clojure "0.37.1"]
                 [de.active-group/active-logger "0.2.0"]
                 [metabase/saml20-clj "2.0.0"]
                 [clojure.java-time "0.3.2"]
                 [org.clojure/data.zip "0.1.1"]
                 [compojure                 "1.3.4"]
                 [ring/ring-core            "1.3.1"]]
  :jvm-opts ["-server"]
  :target-path "target/%s"
  :dev {:resource-paths ["test-resources"]})
