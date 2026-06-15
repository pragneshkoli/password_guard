## 1.0.0

* Initial release
* Argon2id password hashing (OWASP recommended defaults)
* bcrypt password hashing (cost factor 12 default)
* PBKDF2-HMAC-SHA256 password hashing (600,000 iterations default)
* Auto salt generation (16 bytes, Base64)
* Pepper support via inline string, `EnvPepperProvider`, `MemoryPepperProvider`
* Self-contained encoded hash format (`$pg$<algorithm>$v1$<params>$<salt>$<hash>`)
* Password verification with constant-time comparison
* Password migration detection (`needsRehash`)
* Password strength checker (score 0–100, StrengthLevel enum, suggestions)
* Password policy validation (min/max length, charset rules, banned passwords)
* Secure random utilities (`SecureRandom.bytes`, `.base64`, `.hex`)
* Full exception hierarchy (`PasswordGuardException` and subtypes)
* Zero Flutter dependency — works in any Dart runtime
* State management agnostic API
