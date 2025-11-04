use bcrypt::{hash, verify, DEFAULT_COST};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

const JWT_SECRET: &str = "b53e8a3a0a46d1e06a93a1260810edc5ed7419d40beddffc72f040c89bcce50f1825e6a6b0662ab912c9699b0d2a1c527285ca4341de4d34ef041cecbff79d68";

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub user_id: Uuid,
    pub email: String,
    pub exp: usize,
}

pub struct AuthService;

impl AuthService {
    pub fn hash_password(password: &str) -> Result<String, String> {
        hash(password, DEFAULT_COST).map_err(|e| format!("Failed to hash password: {}", e))
    }

    pub fn verify_password(password: &str, hash: &str) -> Result<bool, String> {
        verify(password, hash).map_err(|e| format!("Failed to verify password: {}", e))
    }

    pub fn generate_token(user_id: Uuid, email: String) -> Result<String, String> {
        let exp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as usize
            + 86400 * 7; // 7 days

        let claims = Claims {
            user_id,
            email,
            exp,
        };

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(JWT_SECRET.as_ref()),
        )
        .map_err(|e| format!("Failed to generate token: {}", e))
    }

    pub fn verify_token(token: &str) -> Result<Claims, String> {
        decode::<Claims>(
            token,
            &DecodingKey::from_secret(JWT_SECRET.as_ref()),
            &Validation::default(),
        )
        .map(|data| data.claims)
        .map_err(|e| format!("Invalid token: {}", e))
    }

    pub fn hash_api_key(api_key: &str) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(api_key.as_bytes());
        let result = hasher.finalize();
        hex::encode(result)
    }
}
