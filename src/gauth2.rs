use std::io::{BufRead, Write};

use crate::{error, info, util};

#[derive(serde_derive::Serialize, serde_derive::Deserialize, Debug)]
pub struct TokenData {
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

/// アクセストークン情報
#[derive(serde_derive::Serialize, serde_derive::Deserialize, Debug)]
pub struct TokenVerificationResult {
	///
	access_type: String,
	///
	aud: String,
	///
	azp: String,
	/// メールアドレス
	email: String,
	/// ユーザーのメールアドレスが確認済みであれば true、そうでない場合は false。
	email_verified: String,
	///
	exp: String,
	/// アクセス トークンの残りの有効期間（秒）
	expires_in: String,
	/// access_token によって付与されるアクセス スコープ
	scope: String,
	/// ユーザー ID。すべての Google アカウントの中で一意であり、再利用されることはありません。
	sub: String,
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

/// Google OAuth による認可手続き要求します。
pub fn begin_auth(client_id: &str, redirect_uri: &str, state: &str, code_challenge: &str) -> Result<(), Box<dyn std::error::Error>> {
	let scopes = "openid profile email";

	let url = format!(
            "https://accounts.google.com/o/oauth2/v2/auth?response_type=code&scope={scopes}&redirect_uri={redirect_uri}&client_id={client_id}&state={state}&code_challenge={code_challenge}&code_challenge_method=S256",
            scopes = util::urlencode(&scopes),
            redirect_uri = util::urlencode(&redirect_uri),
            client_id = client_id,
            state = util::urlencode(&state),
            code_challenge = code_challenge
		);

	util::open_browser(&url)?;

	return Ok(());
}

/// 接続を開始します。
fn accept_peer(mut stream: std::net::TcpStream) -> Result<std::collections::HashMap<String, String>, Box<dyn std::error::Error>> {
	info!("着信あり");

	let buf_reader = std::io::BufReader::new(&mut stream);
	let http_request: Vec<_> = buf_reader.lines().map(|result| result.unwrap()).take_while(|line| !line.is_empty()).collect();

	let q = util::diagnose_http_request(&http_request);
	info!("REQUEST> {}", serde_json::to_string_pretty(&q)?);

	let response = format!("HTTP/1.1 200 OK\r\n\r\nOk.");
	stream.write(response.as_bytes()).unwrap();

	return Ok(q);
}

/// HTTP サーバーを立ち上げます。
/// Google OAuth 2.0 のコールバック用です。
///
/// # Arguments
/// * `port` - ポート番号
///
/// # Returns
/// code, url を受け取ります。
fn recv_response(port: u16) -> Result<(String, String), Box<dyn std::error::Error>> {
	use util::MapHelper;

	// Google から ローカルにリダイレクトされるまで待機します。
	// TODO: タイムアウトする仕組み
	info!("ローカルサーバーを起動しています...");
	let address = format!("127.0.0.1:{}", port);
	let listener = std::net::TcpListener::bind(&address)?;

	// non-blocking にすることで、accept がブロックしないようにする
	listener.set_nonblocking(true)?;

	// 簡易的なストップウォッチ
	let stop_watch = util::SimpleStopWatch::new();

	info!("リクエストを待機しています...");
	let mut query = std::collections::HashMap::new();
	for status in listener.incoming() {
		// 120秒で待ち受けを解除
		if 120 <= stop_watch.elapsed().as_secs() {
			return Err("認可手続きの待機時間が120秒を超えたため、手続きはタイムアウトしました。".into());
		}

		if status.is_err() {
			let err = status.err().unwrap();
			if err.kind() == std::io::ErrorKind::WouldBlock {
				std::thread::sleep(std::time::Duration::from_millis(100));
				continue;
			}
			error!("復旧不能なエラーです。理由: {:?}", err);
			break;
		}

		query = accept_peer(status.unwrap())?;

		break;
	}

	// 初めに error を取得する
	let error = query.get_string("error");
	if error != "" {
		return Err(error.into());
	}

	// code を取得する
	let code = query.get_string("code");
	// state を取得する
	let state = query.get_string("state");

	// 1回で終了する

	return Ok((code, state));
}

/// code などを使って、アクセストークンを取得します。
fn exchange_code_to_tokens(
	client_id: &str,
	client_secret: &str,
	state: &str,
	code: &str,
	code_verifier: &str,
	redirect_uri: &str,
) -> Result<TokenData, Box<dyn std::error::Error>> {
	let url = "https://www.googleapis.com/oauth2/v4/token";
	// let url = "https://oauth2.googleapis.com/token"; // こっちでもOK(もしかしたらエイリアスなのかもしれない)

	let mut params = std::collections::HashMap::new();
	params.insert("code", code);
	params.insert("client_id", client_id);
	params.insert("state", &state);
	params.insert("scope", "");
	params.insert("client_secret", client_secret);
	params.insert("redirect_uri", redirect_uri);
	params.insert("grant_type", "authorization_code");
	params.insert("code_verifier", &code_verifier);

	let text = util::http_post(url, &params)?;

	let token_info: TokenData = serde_json::from_str(&text)?;

	return Ok(token_info);
}

pub struct GoogleOAuth2 {
	client_id: String,
	client_secret: String,
	token_data: TokenData,
}

impl GoogleOAuth2 {
	/// コンストラクター
	///
	/// 新しいインスタンスを返します。
	pub fn new(client_id: &str, client_secret: &str) -> Self {
		return Self {
			client_id: client_id.to_string(),
			client_secret: client_secret.to_string(),
			token_data: TokenData {
				access_token: "".to_string(),
				expires_in: 0,
				id_token: None,
				refresh_token: "".to_string(),
				scope: "".to_string(),
				token_type: "".to_string(),
			},
		};
	}

	/// 認可手続きを行います。
	///
	/// 成功した場合は、アクセストークンを返します。
	pub fn begin(&mut self) -> Result<(), Box<dyn std::error::Error>> {
		info!("認可手続きを開始しています...");

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
		begin_auth(&self.client_id, &redirect_uri, &state, &code_challenge)?;

		// ========== HTTP サーバーを立ち上げてリダイレクトを待つ ==========
		// 応答を受け取るための HTTP サーバーを立ち上げます。
		let (code, state) = recv_response(port)?;

		// ========== トークンに変換 >> Google API ==========
		// アクセストークンをリクエスト
		let token_info = exchange_code_to_tokens(&self.client_id, &self.client_secret, &state, &code, &code_verifier, &redirect_uri)?;
		info!("GOOGLE> token_info: {}", serde_json::to_string_pretty(&token_info)?);

		self.token_data = token_info;

		return Ok(());
	}

	/// トークンの有効性を確認します。
	pub fn verify_access_token(&self) -> Result<TokenVerificationResult, Box<dyn std::error::Error>> {
		let access_token = &self.token_data.access_token;
		let uri = format!("https://oauth2.googleapis.com/tokeninfo?access_token={}", access_token);
		let text = util::http_get(&uri)?;
		let token_info: TokenVerificationResult = serde_json::from_str(&text)?;

		return Ok(token_info);
	}

	/// ユーザープロファイルを問い合わせます。
	pub fn query_user_info(&self) -> Result<UserProfile, Box<dyn std::error::Error>> {
		let access_token = &self.token_data.access_token;
		let url = "https://www.googleapis.com/oauth2/v3/userinfo";

		let mut headers = reqwest::header::HeaderMap::new();
		headers.insert("Authorization", reqwest::header::HeaderValue::from_str(&format!("Bearer {}", access_token)).unwrap());

		let client = reqwest::blocking::Client::new();
		let response = client.get(url).headers(headers).send().unwrap();
		let text = response.text().unwrap();

		let user_profile: UserProfile = serde_json::from_str(&text).unwrap();

		return Ok(user_profile);
	}
}
