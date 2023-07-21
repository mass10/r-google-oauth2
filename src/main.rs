//!
//! Rust + Google OAuth 2.0 のサンプル
//!
//! # References
//! - [モバイル &デスクトップ アプリ向け OAuth 2.0](https://developers.google.com/identity/protocols/oauth2/native-app?hl=ja)

mod configuration;
mod service;
mod util;

/// Rust アプリケーションのエントリーポイント
fn main() {
	// コマンドラインオプション
	let args: Vec<String> = std::env::args().skip(1).collect();
	let mut options = getopts::Options::new();
	options.opt("h", "help", "Usage", "FLAG", getopts::HasArg::No, getopts::Occur::Optional);
	let result = options.parse(args);
	if result.is_err() {
		let err = result.err().unwrap();
		println!("{}", err);
		println!("{}", options.usage("r-google-oauth2-sample: Rust + Google OAuth 2.0 のサンプル"));
		std::process::exit(1);
	}
	let matches = result.unwrap();

	if matches.opt_present("help") {
		println!("{}", options.usage("r-google-oauth2-sample: Rust + Google OAuth 2.0 のサンプル"));
		std::process::exit(0);
	}

	// client_secret*.json を検出
	let result = configuration::configure();
	if result.is_err() {
		let err = result.err().unwrap();
		error!("{}", err);
		std::process::exit(1);
	}
	let client_secret = result.unwrap();

	// Google OAuth 2.0 のテスト
	let result = service::execute_oauth_example(&client_secret.installed.client_id, &client_secret.installed.client_secret);
	if result.is_err() {
		let err = result.err().unwrap();
		error!("{}", err);
		std::process::exit(1);
	}

	info!("Ok.");
}
