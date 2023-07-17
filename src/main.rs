//!
//! Rust + Google OAuth 2.0 のサンプル
//!
//! # References
//! - [モバイル &デスクトップ アプリ向け OAuth 2.0](https://developers.google.com/identity/protocols/oauth2/native-app?hl=ja)

use std::io::{BufRead, Write};

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
		let current_timestamp = get_current_timestamp();
		let pid = std::process::id();
		let _ = std::format_args!("{}", line);
        println!("{} ({}) [info] {}", current_timestamp, pid, line);
    };
}

#[macro_export]
macro_rules! error {
    ($($arg:tt)*) => {
		let line = format!($($arg)*);
		let current_timestamp = get_current_timestamp();
		let pid = std::process::id();
		let _ = std::format_args!("{}", line);
        println!("{} ({}) [error] {}", current_timestamp, pid, line);
    };
}

/// Rust アプリケーションのエントリーポイント
fn main() {
	// コマンドラインオプションを解析する
	let args: Vec<String> = std::env::args().skip(1).collect();
	let mut options = getopts::Options::new();
	options.opt("h", "help", "Usage", "FLAG", getopts::HasArg::No, getopts::Occur::Optional);
	let result = options.parse(args);
	if result.is_err() {
		let err = result.err().unwrap();
		println!("{}", err);
		println!("{}", options.usage(""));
		std::process::exit(1);
	}
	let matches = result.unwrap();

	if matches.opt_present("h") {
		println!("{}", options.usage(""));
		std::process::exit(0);
	}

	// Google OAuth 2.0 のテスト
	let result = execute_oauth_example();
	if result.is_err() {
		let err = result.err().unwrap();
		error!("{}", err);
		std::process::exit(1);
	}

	info!("Ok.");
}

/// Google OAuth 2.0 のテスト
fn execute_oauth_example() -> Result<(), Box<dyn std::error::Error>> {
	// client_secret*.json を検出
	let client_secret = configure()?;

	// ランダムなポートを選択します。
	let port = select_random_tcp_port()?;

	// リダイレクトURI(必須)
	let redirect_uri = format!("http://localhost:{}", port);
	// 状態識別用(推奨)
	let state = generate_random_string(32);
	// コード検証ツール(推奨)
	let code_verifier = generate_random_string(32);
	// コードチャレンジ(推奨)
	let code_challenge = generate_code_challenge(&code_verifier);

	// Google OAuth による認可手続き要求します。
	begin_google_oauth(&client_secret.installed.client_id, &state, &code_challenge, &redirect_uri)?;

	// 応答を受け取るための HTTP サーバーを立ち上げます。
	let (code, state) = recv_response(port, &redirect_uri)?;

	// アクセストークンをリクエスト
	let token_info = exchange_code_to_tokens(
		&client_secret.installed.client_id,
		&client_secret.installed.client_secret,
		&state,
		&code,
		&code_verifier,
		&redirect_uri,
	)?;

	// user profile を問い合わせ
	let user_profile = query_user_info(&token_info.access_token)?;

	info!("ユーザープロファイル> {:?}", user_profile);

	return Ok(());
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

fn diagnose_http_request(http_request: &Vec<String>) -> std::collections::HashMap<String, String> {
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

fn accept_peer(mut stream: std::net::TcpStream) -> Result<std::collections::HashMap<String, String>, Box<dyn std::error::Error>> {
	info!("着信あり");

	let buf_reader = std::io::BufReader::new(&mut stream);
	let http_request: Vec<_> = buf_reader.lines().map(|result| result.unwrap()).take_while(|line| !line.is_empty()).collect();

	info!("REQUEST>");
	let q = diagnose_http_request(&http_request);
	println!("    {:?}", q);

	let response = format!("HTTP/1.1 200 OK\r\n\r\nOk.");
	stream.write(response.as_bytes()).unwrap();

	return Ok(q);
}

/// HTTP サーバーを立ち上げます。
/// Google OAuth 2.0 のコールバック用です。
///
/// # Arguments
/// * `port` - ポート番号
/// * `redirect_uri` - リダイレクトURI
///
/// # Returns
/// code, url を受け取ります。
fn recv_response(port: u16, _redirect_uri: &str) -> Result<(String, String), Box<dyn std::error::Error>> {
	info!("ローカルサーバーを起動しています...");

	// Google から ローカルにリダイレクトされるまで待機します。
	let address = format!("127.0.0.1:{}", port);
	let listener = std::net::TcpListener::bind(&address)?;

	// リクエスト全体を受け取る
	info!("リクエストを待機しています...");
	let (stream, _) = listener.accept()?;
	let query = accept_peer(stream)?;

	// 初めに error を取得する
	if query.contains_key("error") {
		let error = query.get("error").unwrap();
		return Err(error.to_string().into());
	}

	// code を取得する
	let code = if query.contains_key("code") {
		query.get("code").unwrap().to_string()
	} else {
		String::new()
	};

	// state を取得する
	let state = if query.contains_key("state") {
		query.get("state").unwrap().to_string()
	} else {
		String::new()
	};

	// 1回で終了する

	return Ok((code, state));
}

/// 使用可能な TCP ポートをランダムに選択します。
fn select_random_tcp_port() -> Result<u16, Box<dyn std::error::Error>> {
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
fn open_browser(url: &str) -> Result<(), Box<dyn std::error::Error>> {
	info!("OPEN> {}", url);
	open::that(url)?;
	return Ok(());
}

/// URL エンコーディング
fn urlencode(s: &str) -> String {
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

/// Google OAuth による認可手続き要求します。
fn begin_google_oauth(client_id: &str, state: &str, code_challenge: &str, redirect_uri: &str) -> Result<(), Box<dyn std::error::Error>> {
	let scopes = "openid profile email";

	let url = format!(
        "https://accounts.google.com/o/oauth2/v2/auth?response_type=code&scope={scopes}&redirect_uri={redirect_uri}&client_id={client_id}&state={state}&code_challenge={code_challenge}&code_challenge_method=S256",
        scopes=urlencode(&scopes),
        redirect_uri=urlencode(redirect_uri),
        client_id=client_id,
        state=urlencode(state),
        code_challenge=code_challenge);

	open_browser(&url)?;

	return Ok(());
}

fn enumerate_client_secret(location: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
	let mut result: Vec<String> = vec![];
	let unknown = std::path::Path::new(location);
	if unknown.is_file() {
		let file_name = unknown.file_name().unwrap().to_str().unwrap();
		if file_name.starts_with("client_secret") && file_name.ends_with(".json") {
			let path = unknown.to_str().unwrap();
			let path = path.to_string();
			result.push(path);
			return Ok(result);
		}
	} else if unknown.is_dir() {
		for entry in std::fs::read_dir(unknown)? {
			let entry = entry?;
			let path = entry.path();
			let mut tmp = enumerate_client_secret(path.to_str().unwrap())?;
			result.append(&mut tmp);
		}
		return Ok(result);
	}
	return Ok(result);
}

fn configure() -> Result<ClientSecret, Box<dyn std::error::Error>> {
	let location = ".\\";

	let files = enumerate_client_secret(location)?;
	if files.len() == 0 {
		info!("ファイルなし");
		return Err("No client secret found".into());
	}

	for file in files {
		let result = parse_client_secret(&file);
		if result.is_err() {
			info!("パースエラー {:?}", file);
			continue;
		}
		let client_secret = result.unwrap();
		if client_secret.installed.client_id.len() > 0 && client_secret.installed.client_secret.len() > 0 {
			return Ok(client_secret);
		}
	}

	return Err("No client secret found".into());
}

/// client_secret*.json をパースします。
fn parse_client_secret(path: &str) -> Result<ClientSecret, Box<dyn std::error::Error>> {
	let file = std::fs::File::open(path)?;
	let reader = std::io::BufReader::new(file);
	let client_secret: ClientSecret = serde_json::from_reader(reader)?;
	return Ok(client_secret);
}

#[derive(serde_derive::Serialize, serde_derive::Deserialize, Debug)]
struct Installed {
	client_id: String,
	client_secret: String,
	redirect_uris: Vec<String>,
	auth_uri: String,
	token_uri: String,
}

#[derive(serde_derive::Serialize, serde_derive::Deserialize, Debug)]
struct ClientSecret {
	installed: Installed,
}

// https://oauth2.googleapis.com/tokeninfo

/// BASE64 文字列の特別な変換
fn fix_base64_string(s: &str) -> String {
	let s = s.replace("=", "");
	let s = s.replace("+", "-");
	let s = s.replace("/", "_");
	return s;
}

/// コード検証ツールとしての文字列を生成します。
fn generate_random_string(size: u32) -> String {
	let buffer = generate_random_u8_array(size);
	let s = encode_base64(&buffer);
	return fix_base64_string(&s);
}

#[derive(serde_derive::Serialize, serde_derive::Deserialize, Debug)]
struct TokenInfo {
	/// アクセストークン
	access_token: String,
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

/// code などを使って、アクセストークンを取得します。
fn exchange_code_to_tokens(
	client_id: &str,
	client_secret: &str,
	state: &str,
	code: &str,
	code_verifier: &str,
	redirect_uri: &str,
) -> Result<TokenInfo, Box<dyn std::error::Error>> {
	let url = "https://www.googleapis.com/oauth2/v4/token";
	// let url = "https://oauth2.googleapis.com/token"; // こっちでもOK
	let mut params = std::collections::HashMap::new();
	params.insert("code", code);
	params.insert("client_id", client_id);
	params.insert("state", &state);
	params.insert("scope", "");
	params.insert("client_secret", client_secret);
	params.insert("redirect_uri", redirect_uri);
	params.insert("grant_type", "authorization_code");
	params.insert("code_verifier", &code_verifier);
	let client = reqwest::blocking::Client::new();
	let response = client.post(url).form(&params).send()?;
	let text = response.text()?;
	let token_info: TokenInfo = serde_json::from_str(&text)?;
	info!("GOOGLE> {:?}", &token_info);
	return Ok(token_info);
}

/// SHA256 ハッシュ
fn create_sha256b_hash(s: &str) -> Vec<u8> {
	use sha2::Digest;

	let array = s.as_bytes();
	let mut hasher = sha2::Sha256::new();
	hasher.update(array);
	let result = hasher.finalize();
	return result.as_slice().to_vec();
}

/// code_verifier >> code_challenge
fn generate_code_challenge(s: &str) -> String {
	let buffer = create_sha256b_hash(s);
	let s = encode_base64(&buffer);
	return fix_base64_string(&s);
}

/// BASE64 エンコーディング
fn encode_base64(buffer: &[u8]) -> String {
	use base64::Engine;

	let result = base64::engine::general_purpose::STANDARD.encode(buffer);
	return result;
}

/// ランダムな u8 バイト配列を生成します。
fn generate_random_u8_array(length: u32) -> Vec<u8> {
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
struct UserProfile {
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

/// ユーザープロファイルを問い合わせます。
fn query_user_info(access_token: &str) -> Result<UserProfile, Box<dyn std::error::Error>> {
	let url = "https://www.googleapis.com/oauth2/v3/userinfo";
	let mut headers = reqwest::header::HeaderMap::new();
	headers.insert("Authorization", reqwest::header::HeaderValue::from_str(&format!("Bearer {}", access_token)).unwrap());
	let client = reqwest::blocking::Client::new();
	let response = client.get(url).headers(headers).send().unwrap();
	let text = response.text().unwrap();
	let user_profile: UserProfile = serde_json::from_str(&text).unwrap();
	return Ok(user_profile);
}
