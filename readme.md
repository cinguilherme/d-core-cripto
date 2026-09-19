# d-core-cripto

Storage-backed AES-GCM cryptography component for Clojure applications and Duct/Integrant systems.

## Features

- **Integrant / Duct Lifecycle**: `:d-core.core.criptography/storage` dynamically loads cryptographic key material from any `StorageProtocol` backend (Local Disk, MinIO, S3, etc.).
- **AES-GCM AEAD**: Authenticated encryption with associated data using AES/GCM/NoPadding (128-bit authentication tag, 12-byte randomized IV per encryption).
- **Flexible Key Encodings**: Supports `:base64` (default), `:utf8`, or raw byte array key material.
- **Protocol Interoperability**: Implements `d-core.core.criptography.protocol/CriptographyProtocol` from `d-core-std`.

## Installation

Add to your `deps.edn`:

```clojure
org.clojars.cinguilherme/d-core-cripto {:mvn/version "0.1.0"}
```

Or for local development:

```clojure
org.clojars.cinguilherme/d-core-cripto {:local/root "../d-core-cripto"}
```

## Quick Start

### Integrant / Duct Configuration

```clojure
{:d-core.core.criptography/storage
 {:storage #ig/ref :d-core.core.storage/common
  :key-path "keys/app.key"
  :encoding :base64
  :algorithm "AES"}}
```

### Usage

```clojure
(require '[d-core.core.criptography.protocol :as crypto])

(let [encrypted (crypto/encrypt crypto-comp "sensitive data")
      decrypted (crypto/decrypt crypto-comp encrypted)]
  (assert (= "sensitive data" decrypted)))
```

## Documentation

See [docs/criptography.md](docs/criptography.md) for architecture, configuration options, and key formats.
