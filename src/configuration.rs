use crate::info;

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

/// client_secret*.json を列挙します。
///
/// # Arguments
/// * `location` - 検索を開始する場所
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

/// コンフィギュレーションを行います。
pub fn configure() -> Result<ClientSecret, Box<dyn std::error::Error>> {
	// カレントディレクトリ配下の client_secret*.json を検索
	let files = enumerate_client_secret(".")?;
	if files.len() == 0 {
		return Err("client secret がみつかりません。".into());
	}

	for file in files {
		let result = parse_client_secret(&file);
		if result.is_err() {
			info!("パースエラー {:?}", file);
			continue;
		}
		// パースに成功した最初のファイルを採用
		return Ok(result.unwrap());
	}

	return Err("client secret がみつかりません。".into());
}

/// client_secret*.json をパースします。
///
/// # Arguments
/// * `path` - ファイルパス
fn parse_client_secret(path: &str) -> Result<ClientSecret, Box<dyn std::error::Error>> {
	let file = std::fs::File::open(path)?;
	let reader = std::io::BufReader::new(file);
	let client_secret: ClientSecret = serde_json::from_reader(reader)?;
	if client_secret.installed.client_id.is_empty() {
		return Err("無効な client id です。".into());
	}
	if client_secret.installed.client_secret.is_empty() {
		return Err("無効な client secret です。".into());
	}
	return Ok(client_secret);
}
