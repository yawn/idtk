use ring::{
    aead::Aad,
    hmac::{Context, HMAC_SHA256, Key},
    rand::{SecureRandom, SystemRandom},
};
use thiserror::Error;
use time::{Duration, OffsetDateTime};

#[derive(Debug, Error, PartialEq)]
pub enum Error {
    #[error("ID generation failed")]
    IDGenerationFailed,

    #[error("invalid token signature")]
    TokenInvalidSignature,

    #[error("token expired")]
    TokenExpired {
        iat: OffsetDateTime,
        lifetime: Duration,
        now: OffsetDateTime,
    },

    #[error("timestamp invalid encoding")]
    TimestampInvalidEncoding,

    #[error("timestamp invalid")]
    TimestampInvalid(#[from] time::error::ComponentRange),
}

pub type Result<T> = std::result::Result<T, Error>;

pub struct Authority {
    clock: fn() -> OffsetDateTime,
    rng: SystemRandom,
    key: Key,
}

impl Authority {
    pub fn new(key: &[u8; Token::SIZE_TAG]) -> Self {
        let key = Key::new(HMAC_SHA256, key);
        let rng = SystemRandom::new();

        Self {
            key,
            clock: OffsetDateTime::now_utc,
            rng,
        }
    }

    pub fn create_token<A: AsRef<[u8]>>(&self, aad: Aad<A>) -> Result<Token> {
        let iat = (self.clock)().unix_timestamp().to_be_bytes();

        let mut id = [0u8; Token::SIZE_ID];
        self.rng
            .fill(&mut id)
            .map_err(|_| Error::IDGenerationFailed)?;

        let mut ctx = Context::with_key(&self.key);

        ctx.update(&iat);
        ctx.update(&id);
        ctx.update(aad.as_ref());

        let tag = ctx.sign();

        let tok = Token::new(&iat, &id, tag.as_ref());

        Ok(tok)
    }

    pub fn verify_token<A: AsRef<[u8]>>(
        &self,
        tok: &Token,
        lifetime: Duration,
        aad: Aad<A>,
    ) -> Result<()> {
        let mut ctx = Context::with_key(&self.key);

        ctx.update(tok.iat());
        ctx.update(tok.id());
        ctx.update(aad.as_ref());

        let ctag = ctx.sign();

        if ctag.as_ref() != tok.tag() {
            return Err(Error::TokenInvalidSignature);
        }

        let now = (self.clock)();
        let iat = tok.timestamp()?;

        if now > iat + lifetime {
            return Err(Error::TokenExpired { iat, lifetime, now });
        }

        Ok(())
    }
}

#[derive(Debug)]
pub struct Token([u8; Token::SIZE]);

impl Token {
    pub const SIZE: usize = Token::SIZE_IAT + Token::SIZE_ID + Token::SIZE_TAG;

    pub const SIZE_IAT: usize = 8;
    pub const SIZE_ID: usize = 16;
    pub const SIZE_TAG: usize = 32;

    fn new(iat: &[u8], id: &[u8], tag: &[u8]) -> Self {
        let mut buf: [u8; Self::SIZE] = [0; Self::SIZE];

        buf[..Self::SIZE_IAT].copy_from_slice(iat);
        buf[Self::SIZE_IAT..Self::SIZE_IAT + Self::SIZE_ID].copy_from_slice(id);
        buf[Self::SIZE_IAT + Self::SIZE_ID..].copy_from_slice(tag);

        Self(buf)
    }

    pub fn iat(&self) -> &[u8] {
        &self.0[..Self::SIZE_IAT]
    }

    pub fn timestamp(&self) -> Result<OffsetDateTime> {
        let iat = i64::from_be_bytes(
            self.iat()
                .try_into()
                .map_err(|_| Error::TimestampInvalidEncoding)?,
        );

        let iat = OffsetDateTime::from_unix_timestamp(iat).map_err(Error::TimestampInvalid)?;

        Ok(iat)
    }

    pub fn id(&self) -> &[u8] {
        &self.0[Self::SIZE_IAT..Self::SIZE_IAT + Self::SIZE_ID]
    }

    fn tag(&self) -> &[u8] {
        &self.0[Self::SIZE_IAT + Self::SIZE_ID..]
    }
}

#[cfg(feature = "base32")]
impl std::fmt::Display for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", fast32::base32::CROCKFORD_LOWER.encode(&self.0))
    }
}

#[cfg(feature = "base64")]
impl std::fmt::Display for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", fast32::base64::RFC4648_URL_NOPAD.encode(&self.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid() {
        let tat = Authority::new(&[0u8; Token::SIZE_TAG]);
        let aad = Aad::empty();

        let t = tat.create_token(aad).unwrap();

        assert_eq!(Ok(()), tat.verify_token(&t, Duration::seconds(5), aad));
    }

    #[test]
    fn test_invalid_aad() {
        let tat = Authority::new(&[0u8; Token::SIZE_TAG]);
        let aad = Aad::empty();

        let t = tat.create_token(aad).unwrap();

        let aad = Aad::from(b"test");

        assert_eq!(
            Err(Error::TokenInvalidSignature),
            tat.verify_token(&t, Duration::seconds(5), aad)
        );
    }

    #[test]
    fn test_invalid_key() {
        let tat = Authority::new(&[0u8; Token::SIZE_TAG]);
        let aad = Aad::empty();

        let t = tat.create_token(aad).unwrap();

        let tat = Authority::new(&[1u8; Token::SIZE_TAG]);

        assert_eq!(
            Err(Error::TokenInvalidSignature),
            tat.verify_token(&t, Duration::seconds(5), aad)
        );
    }

    #[test]
    fn test_invalid_timestamp() {
        let mut tat = Authority::new(&[0u8; Token::SIZE_TAG]);

        let aad = Aad::empty();

        let t = tat.create_token(aad).unwrap();

        tat.clock = || OffsetDateTime::from_unix_timestamp(2_147_483_647).unwrap();

        assert_eq!(
            Err(Error::TokenExpired {
                iat: t.timestamp().unwrap(),
                lifetime: Duration::seconds(5),
                now: OffsetDateTime::from_unix_timestamp(2_147_483_647).unwrap(),
            }),
            tat.verify_token(&t, Duration::seconds(5), aad)
        );
    }

    #[cfg(feature = "base32")]
    #[test]
    fn test_token_display_base32() {
        let iat = [0u8; 8];
        let id = [1u8; 16];
        let tag = [2u8; 32];

        let token = Token::new(&iat, &id, &tag);
        let display = format!("{}", token);

        assert!(!display.is_empty());
        assert!(display.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[cfg(feature = "base64")]
    #[test]
    fn test_token_display_base64() {
        let iat = [0u8; 8];
        let id = [1u8; 16];
        let tag = [2u8; 32];

        let token = Token::new(&iat, &id, &tag);
        let display = format!("{}", token);

        assert!(!display.is_empty());
        assert!(
            display
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        );
    }
}
