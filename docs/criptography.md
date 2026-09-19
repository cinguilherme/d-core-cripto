## Cryptography (`d-core-cripto`)

`d-core-cripto` provides a production-grade, storage-backed AES-GCM implementation of `d-core.core.criptography.protocol/CriptographyProtocol`.

### Component Config (Integrant/Duct)

Key: `:d-core.core.criptography/storage`

Options:
- `:storage` (required): Component implementing `d-core.core.storage.protocol/StorageProtocol` (e.g. `:d-core.core.storage/common`, `:d-core.core.storage/local-disk`, MinIO, S3).
- `:key-path` (required): Relative storage path to the key material (e.g., `"keys/master.key"`).
- `:encoding` (optional, default `:base64`): Encoding format of the key material stored in `:storage`. Supported: `:base64`, `:utf8`. Raw `byte[]` is also handled directly.
- `:algorithm` (optional, default `"AES"`): Key algorithm.
- `:storage-opts` (optional, default `{}`): Additional options passed to `storage/storage-get`.

```clj
{:d-core.core.criptography/storage
 {:storage #ig/ref :d-core.core.storage/common
  :key-path "keys/app.key"
  :encoding :base64
  :algorithm "AES"}}
```

### Encryption Format

- **Cipher**: `AES/GCM/NoPadding`
- **IV / Nonce**: 12 bytes randomly generated using `java.security.SecureRandom` on every encryption call.
- **Tag**: 128-bit authentication tag appended by GCM mode.
- **Output**: Binary `byte[]` containing `[12-byte IV | Ciphertext + Tag]`.
- **Integrity**: Decryption validates the GCM authentication tag. Tampered ciphertexts or invalid keys throw `javax.crypto.AEADBadTagException`.
