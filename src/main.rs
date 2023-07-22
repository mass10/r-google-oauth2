//!
//! Rust + Google OAuth 2.0 のサンプル
//!
//! # References
//! - [モバイル &デスクトップ アプリ向け OAuth 2.0](https://developers.google.com/identity/protocols/oauth2/native-app?hl=ja)

mod configuration;
mod gauth2;
mod util;

/// Rust アプリケーションのエントリーポイント
fn main() {
	// client_secret*.json を検出
	let result = configuration::configure();
	if result.is_err() {
		let err = result.err().unwrap();
		error!("{}", err);
		std::process::exit(1);
	}
	let client_secret = result.unwrap();

	// Google OAuth 2.0 のテスト
	let result = execute_oauth_example(&client_secret.installed.client_id, &client_secret.installed.client_secret);
	if result.is_err() {
		let err = result.err().unwrap();
		error!("{}", err);
		std::process::exit(1);
	}

	info!("Ok.");
}

/// Google OAuth 2.0 のテスト
fn execute_oauth_example(client_id: &str, client_secret: &str) -> Result<(), Box<dyn std::error::Error>> {
	let mut service = crate::gauth2::GoogleOAuth2::new(client_id, client_secret);

	// ========== ブラウザーで認可画面を開く ==========
	// Google OAuth による認可手続きの開始を要求します。
	service.begin()?;

	// ========== アクセストークンの確認 >> Google API ==========
	info!("セッションの妥当性を確認しています...");
	let result = service.verify_access_token()?;
	info!("GOOGLE> verify: {}", serde_json::to_string_pretty(&result)?);

	// ========== ユーザーの情報を要求 >> Google API ==========
	info!("ユーザープロフィールを問い合わせています...");
	let user_profile = service.query_user_info()?;
	info!("GOOGLE> user_profile: {}", serde_json::to_string_pretty(&user_profile)?);

	return Ok(());
}
