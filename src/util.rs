//!
//! Rust + Google OAuth 2.0 のサンプル
//!
//! # References
//! - [モバイル &デスクトップ アプリ向け OAuth 2.0](https://developers.google.com/identity/protocols/oauth2/native-app?hl=ja)

/// 現在のタイムスタンプを取得します。
pub fn get_current_timestamp() -> String {
	let now = chrono::Local::now();
	let timestamp = now.format("%Y-%m-%d %H:%M:%S%.3f").to_string();
	timestamp
}

#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => {
		let line = format!($($arg)*);
		let current_timestamp = crate::util::get_current_timestamp();
		let pid = std::process::id();
		let _ = std::format_args!("{}", line);
        println!("{} ({}) [info] {}", current_timestamp, pid, line);
    };
}

#[macro_export]
macro_rules! error {
    ($($arg:tt)*) => {
		let line = format!($($arg)*);
		let current_timestamp = crate::util::get_current_timestamp();
		let pid = std::process::id();
		let _ = std::format_args!("{}", line);
        println!("{} ({}) [error] {}", current_timestamp, pid, line);
    };
}

fn split_querystring(url: &str) -> std::collections::HashMap<String, String> {
	if !url.contains("?") {
		return std::collections::HashMap::new();
	}
	let (_, querystring) = url.split_once("?").unwrap();

	let mut query = std::collections::HashMap::new();
	for pair in querystring.split("&") {
		let mut iter = pair.split("=");
		let key = iter.next().unwrap();
		let value = iter.next().unwrap();
		query.insert(key.to_string(), urldecode(value));
	}
	return query;
}

fn retrieve_url(unknown: &str) -> String {
	if !unknown.starts_with("GET /") {
		return String::new();
	}
	let mut items = unknown.split(" ");
	let url = items.nth(1).unwrap();
	return url.to_string();
}

pub fn diagnose_http_request(http_request: &Vec<String>) -> std::collections::HashMap<String, String> {
	for line in http_request {
		let url = retrieve_url(line);
		if url == "" {
			continue;
		}
		return split_querystring(&url);
	}
	return std::collections::HashMap::new();
}

fn urldecode(s: &str) -> String {
	let mut result = String::new();
	let mut i = 0;
	while i < s.len() {
		let c = s.chars().nth(i).unwrap();
		if c == '%' {
			let hex = &s[i + 1..i + 3];
			let n = u8::from_str_radix(hex, 16).unwrap();
			result.push(n as char);
			i += 3;
		} else {
			result.push(c);
			i += 1;
		}
	}
	result
}

/// 使用可能な TCP ポートをランダムに選択します。
pub fn select_random_tcp_port() -> Result<u16, Box<dyn std::error::Error>> {
	for port in 15000..29000 {
		if try_bind_tcp_port(port)? {
			return Ok(port);
		}
	}

	return Err("No port available".into());
}

/// TCP ポートが使用可能かどうかを確認します。
fn try_bind_tcp_port(port: u16) -> Result<bool, Box<dyn std::error::Error>> {
	let address = format!("127.0.0.1:{}", port);
	let result = std::net::TcpListener::bind(&address);
	if result.is_err() {
		return Ok(false);
	}
	return Ok(true);
}

/// ブラウザーを開きます。
pub fn open_browser(url: &str) -> Result<(), Box<dyn std::error::Error>> {
	info!("OPEN> {}", url);
	open::that(url)?;
	return Ok(());
}

/// URL エンコーディング
pub fn urlencode(s: &str) -> String {
	let mut result = String::new();
	for c in s.chars() {
		if c.is_ascii_alphanumeric() {
			result.push(c);
		} else {
			result.push_str(&format!("%{:02X}", c as u8));
		}
	}
	return result;
}

/// QueryString を作成します。
#[allow(unused)]
fn build_query_string(params: &std::collections::HashMap<&str, &str>) -> String {
	let mut query = String::new();
	for (key, value) in params {
		if query == "" {
			query.push('?');
		} else {
			query.push('&');
		}
		query.push_str(key);
		query.push('=');
		query.push_str(&urlencode(value));
	}
	return query;
}

#[derive(serde_derive::Serialize, serde_derive::Deserialize, Debug)]
pub struct Installed {
	pub client_id: String,
	pub client_secret: String,
	pub redirect_uris: Vec<String>,
	pub auth_uri: String,
	pub token_uri: String,
}

#[derive(serde_derive::Serialize, serde_derive::Deserialize, Debug)]
pub struct ClientSecret {
	pub installed: Installed,
}

// https://oauth2.googleapis.com/tokeninfo

/// BASE64 文字列の特別な変換
pub fn fix_base64_string(s: &str) -> String {
	let s = s.replace("=", "");
	let s = s.replace("+", "-");
	let s = s.replace("/", "_");
	return s;
}

/// コード検証ツールとしての文字列を生成します。
pub fn generate_random_string(size: u32) -> String {
	let buffer = generate_random_u8_array(size);
	let s = encode_base64(&buffer);
	return fix_base64_string(&s);
}

#[derive(serde_derive::Serialize, serde_derive::Deserialize, Debug)]
pub struct TokenInfo {
	/// アクセストークン
	pub access_token: String,
	/// アクセス トークンの残りの有効期間（秒）
	expires_in: u32,
	/// このプロパティは、リクエストに ID スコープ（openid、profile、email など）が含まれる場合にのみ返されます。
	id_token: Option<String>,
	/// 更新トークン
	refresh_token: String,
	/// access_token によって付与されるアクセス スコープ
	scope: String,
	/// 常に Bearer
	token_type: String,
}

/// SHA256 ハッシュ
pub fn create_sha256b_hash(s: &str) -> Vec<u8> {
	use sha2::Digest;

	let array = s.as_bytes();
	let mut hasher = sha2::Sha256::new();
	hasher.update(array);
	let result = hasher.finalize();
	return result.as_slice().to_vec();
}

/// code_verifier >> code_challenge
pub fn generate_code_challenge(s: &str) -> String {
	let buffer = create_sha256b_hash(s);
	let s = encode_base64(&buffer);
	return fix_base64_string(&s);
}

/// BASE64 エンコーディング
pub fn encode_base64(buffer: &[u8]) -> String {
	use base64::Engine;

	let result = base64::engine::general_purpose::STANDARD.encode(buffer);
	return result;
}

/// ランダムな u8 バイト配列を生成します。
pub fn generate_random_u8_array(length: u32) -> Vec<u8> {
	use rand::Rng;
	let mut result: Vec<u8> = vec![];
	for _ in 0..length {
		let value: u8 = rand::thread_rng().gen();
		result.push(value);
	}
	return result;
}

/// ユーザープロファイル
#[derive(serde_derive::Serialize, serde_derive::Deserialize, Debug)]
pub struct UserProfile {
	/// メールアドレス
	email: String,
	/// ユーザーのメールアドレスが確認済みであれば true、そうでない場合は false。
	email_verified: bool,
	/// ユーザーの姓（ラストネーム）
	family_name: String,
	/// ユーザーの名（ファースト ネーム）
	given_name: String,
	/// ユーザーの言語 / 地域
	locale: String,
	/// ユーザーの氏名（表示可能な形式）
	name: String,
	/// ユーザーのプロフィール写真の URL
	picture: String,
	/// ユーザー ID。すべての Google アカウントの中で一意であり、再利用されることはありません。
	sub: String,
}