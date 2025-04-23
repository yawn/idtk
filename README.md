# Identity token (`idtk`)

An identity token is a fixed-sized sequence that prefixes 16-bytes of random data with a 8-byte timestamp, similar to UUIDv7. In contrast to UUIDv7, a SHA256 HMAC signature tag is the final part of an identity token and the timestamp is expected to be validated against some maximum lifetime of the token.

Additional authenticated data (that is not part of the token itself) is supported.

## Example

```
let key = [0u8; Token::SIZE_TAG];
let tat = Authority::new(&key);
let tok = tat.create_token(Aad::empty()).unwrap();

tat.verify_token(&tok, Duration::seconds(5), Aad::empty()).unwrap();
```
