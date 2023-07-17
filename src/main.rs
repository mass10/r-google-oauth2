//!
//! Rust + Google OAuth 2.0 のサンプル
//!
//! # References
//! - [モバイル &デスクトップ アプリ向け OAuth 2.0](https://developers.google.com/identity/protocols/oauth2/native-app?hl=ja)

mod util;

use std::io::{BufRead, Write};

use util::{TokenInfo, UserProfile};

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
	let port = util::select_random_tcp_port()?;

	// リダイレクトURI(必須)
	let redirect_uri = format!("http://localhost:{}", port);
	// 状態識別用(推奨)
	let state = util::generate_random_string(32);
	// コード検証ツール(推奨)
	let code_verifier = util::generate_random_string(32);
	// コードチャレンジ(推奨)
	let code_challenge = util::generate_code_challenge(&code_verifier);

	// ========== ブラウザーで認可画面を開く ==========

	// Google OAuth による認可手続きの開始を要求します。
	begin_google_oauth(&client_secret.installed.client_id, &state, &code_challenge, &redirect_uri)?;

	// ========== HTTP サーバーを立ち上げてリダイレクトを待つ ==========

	// 応答を受け取るための HTTP サーバーを立ち上げます。
	let (code, state) = recv_response(port, &redirect_uri)?;

	// ========== トークンに変換 >> Google API ==========

	// アクセストークンをリクエスト
	let token_info = exchange_code_to_tokens(
		&client_secret.installed.client_id,
		&client_secret.installed.client_secret,
		&state,
		&code,
		&code_verifier,
		&redirect_uri,
	)?;

	// ========== ユーザーの情報を要求 >> Google API ==========

	// user profile を問い合わせ
	let user_profile = query_user_info(&token_info.access_token)?;

	info!("ユーザープロファイル> {:?}", user_profile);

	return Ok(());
}

fn accept_peer(mut stream: std::net::TcpStream) -> Result<std::collections::HashMap<String, String>, Box<dyn std::error::Error>> {
	info!("着信あり");

	let buf_reader = std::io::BufReader::new(&mut stream);
	let http_request: Vec<_> = buf_reader.lines().map(|result| result.unwrap()).take_while(|line| !line.is_empty()).collect();

	info!("REQUEST>");
	let q = util::diagnose_http_request(&http_request);
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

/// Google OAuth による認可手続き要求します。
fn begin_google_oauth(client_id: &str, state: &str, code_challenge: &str, redirect_uri: &str) -> Result<(), Box<dyn std::error::Error>> {
	let scopes = "openid profile email";

	let url = format!(
        "https://accounts.google.com/o/oauth2/v2/auth?response_type=code&scope={scopes}&redirect_uri={redirect_uri}&client_id={client_id}&state={state}&code_challenge={code_challenge}&code_challenge_method=S256",
        scopes=util::urlencode(&scopes),
        redirect_uri=util::urlencode(redirect_uri),
        client_id=client_id,
        state=util::urlencode(state),
        code_challenge=code_challenge);

	util::open_browser(&url)?;

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

fn configure() -> Result<util::ClientSecret, Box<dyn std::error::Error>> {
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
fn parse_client_secret(path: &str) -> Result<util::ClientSecret, Box<dyn std::error::Error>> {
	let file = std::fs::File::open(path)?;
	let reader = std::io::BufReader::new(file);
	let client_secret: util::ClientSecret = serde_json::from_reader(reader)?;
	return Ok(client_secret);
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
