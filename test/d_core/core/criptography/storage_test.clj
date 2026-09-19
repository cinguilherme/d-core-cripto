(ns d-core.core.criptography.storage-test
  (:require [clojure.test :refer [deftest is testing]]
            [d-core.core.criptography.protocol :as protocol]
            [d-core.core.criptography.storage :as storage-crypto]
            [d-core.core.storage.protocol :as storage]
            [integrant.core :as ig])
  (:import (java.util Base64)
           (javax.crypto AEADBadTagException)))

(defn- in-memory-storage
  [data]
  (reify storage/StorageProtocol
    (storage-get [_ key _opts]
      (if-let [v (get data key)]
        {:ok true :value v}
        {:ok false :error-type :not-found :error "Key not found"}))
    (storage-put [_ _ _ _] (throw (ex-info "storage-put not supported in test" {})))
    (storage-delete [_ _ _] (throw (ex-info "storage-delete not supported in test" {})))
    (storage-get-bytes [_ _ _] (throw (ex-info "storage-get-bytes not supported in test" {})))
    (storage-put-bytes [_ _ _ _] (throw (ex-info "storage-put-bytes not supported in test" {})))
    (storage-head [_ _ _] (throw (ex-info "storage-head not supported in test" {})))
    (storage-list [_ _] (throw (ex-info "storage-list not supported in test" {})))))

(deftest storage-cryptography-roundtrip
  (testing "encrypt/decrypt roundtrip from storage key material"
    (let [key-bytes (.getBytes "0123456789ABCDEF" "UTF-8")
          key-b64 (.encodeToString (Base64/getEncoder) key-bytes)
          storage (in-memory-storage {"keys/app.key" key-b64})
          crypto (ig/init-key :d-core.core.criptography/storage
                              {:storage storage
                               :key-path "keys/app.key"})
          payload "secret-envelope"
          enc1 (protocol/encrypt crypto payload)
          enc2 (protocol/encrypt crypto payload)
          dec1 (protocol/decrypt crypto enc1)
          dec2 (protocol/decrypt crypto enc2)]
      (is (= payload dec1))
      (is (= payload dec2))
      (is (not= (seq enc1) (seq enc2)) "GCM should randomize ciphertext via IV"))))

(deftest key-encodings-support
  (testing "Key loaded as raw byte array"
    (let [raw-bytes (.getBytes "0123456789ABCDEF" "UTF-8")
          storage (in-memory-storage {"keys/raw.key" raw-bytes})
          crypto (ig/init-key :d-core.core.criptography/storage
                              {:storage storage
                               :key-path "keys/raw.key"})
          payload "raw-key-test"]
      (is (= payload (protocol/decrypt crypto (protocol/encrypt crypto payload))))))

  (testing "Key loaded as utf8 string"
    (let [utf8-str "0123456789ABCDEF"
          storage (in-memory-storage {"keys/utf8.key" utf8-str})
          crypto (ig/init-key :d-core.core.criptography/storage
                              {:storage storage
                               :key-path "keys/utf8.key"
                               :encoding :utf8})
          payload "utf8-key-test"]
      (is (= payload (protocol/decrypt crypto (protocol/encrypt crypto payload)))))))

(deftest error-conditions
  (testing "Key material not found in storage throws"
    (let [storage (in-memory-storage {})]
      (is (thrown? clojure.lang.ExceptionInfo
                   (ig/init-key :d-core.core.criptography/storage
                                {:storage storage
                                 :key-path "missing.key"})))))

  (testing "Unsupported key encoding throws"
    (let [storage (in-memory-storage {"keys/bad.key" "secret"})]
      (is (thrown? clojure.lang.ExceptionInfo
                   (ig/init-key :d-core.core.criptography/storage
                                {:storage storage
                                 :key-path "keys/bad.key"
                                 :encoding :hex})))))

  (testing "Missing :storage or :key-path throws"
    (is (thrown? clojure.lang.ExceptionInfo
                 (ig/init-key :d-core.core.criptography/storage {:key-path "k"})))
    (is (thrown? clojure.lang.ExceptionInfo
                 (ig/init-key :d-core.core.criptography/storage {:storage :fake})))))

(deftest security-integrity
  (testing "Payload too short to contain IV throws"
    (let [key-bytes (.getBytes "0123456789ABCDEF" "UTF-8")
          key-b64 (.encodeToString (Base64/getEncoder) key-bytes)
          storage (in-memory-storage {"keys/app.key" key-b64})
          crypto (ig/init-key :d-core.core.criptography/storage
                              {:storage storage
                               :key-path "keys/app.key"})]
      (is (thrown? clojure.lang.ExceptionInfo
                   (protocol/decrypt crypto (byte-array 5))))))

  (testing "Corrupted ciphertext / tampered tag throws AEADBadTagException"
    (let [key-bytes (.getBytes "0123456789ABCDEF" "UTF-8")
          key-b64 (.encodeToString (Base64/getEncoder) key-bytes)
          storage (in-memory-storage {"keys/app.key" key-b64})
          crypto (ig/init-key :d-core.core.criptography/storage
                              {:storage storage
                               :key-path "keys/app.key"})
          encrypted (protocol/encrypt crypto "hello world")
          tampered (byte-array encrypted)]
      ;; Tamper with the last byte (authentication tag)
      (aset-byte tampered (dec (alength tampered))
                 (unchecked-byte (bit-xor (aget tampered (dec (alength tampered))) 0x01)))
      (is (thrown? AEADBadTagException
                   (protocol/decrypt crypto tampered))))))
