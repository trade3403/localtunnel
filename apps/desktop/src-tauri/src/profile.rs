//! Non-secret profile only. Tokens are intentionally excluded from disk.
use localtunnel::{client_mixed_configs, ClientMapping, MappingProtocol};
use serde::{Deserialize, Serialize};
use std::{fs, io::{Read, Write}, net::SocketAddr, path::Path};
use tempfile::NamedTempFile;

const LIMIT: u64 = 128 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProfileMapping {
    #[serde(default = "crate::default_protocol")]
    pub protocol: String,
    pub name: String,
    pub local_port: u16,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Profile {
    pub engine: String,
    pub remote: String,
    pub server_key: String,
    pub mappings: Vec<ProfileMapping>,
}

fn validate(profile: &Profile) -> Result<(), String> {
    if profile.engine.len() > 4096 || (!profile.engine.is_empty() && !Path::new(&profile.engine).is_absolute()) {
        return Err("自定义引擎路径须为绝对路径，留空使用内置引擎".into());
    }
    if profile.mappings.is_empty() || profile.mappings.len() > 64 {
        return Err("映射数量须为 1–64".into());
    }
    // Unique placeholders only for core validation, never saved or used to connect.
    let placeholders = (0..profile.mappings.len()).map(|i| format!("{i:032x}")).collect::<Vec<_>>();
    let mappings = profile.mappings.iter().zip(&placeholders).map(|(m, token)| {
        Ok((MappingProtocol::parse(&m.protocol)?, ClientMapping {
            name: &m.name, local: SocketAddr::from(([127, 0, 0, 1], m.local_port)), token,
        }))
    }).collect::<Result<Vec<_>, &str>>().map_err(str::to_owned)?;
    client_mixed_configs(&profile.remote, &mappings, &profile.server_key).map_err(str::to_owned)?;
    Ok(())
}

pub fn save(dir: &Path, profile: &Profile) -> Result<(), String> {
    validate(profile)?;
    let data = serde_json::to_vec_pretty(profile).map_err(|_| "配置序列化失败")?;
    if data.len() as u64 > LIMIT { return Err("配置过大".into()); }
    fs::create_dir_all(dir).map_err(|_| "无法创建配置目录")?;
    let mut file = NamedTempFile::new_in(dir).map_err(|_| "无法创建临时配置")?;
    file.write_all(&data).and_then(|_| file.as_file().sync_all()).map_err(|_| "无法保存配置")?;
    file.persist(dir.join("profile.json")).map_err(|_| "无法替换配置文件")?;
    Ok(())
}

pub fn load(dir: &Path) -> Result<Option<Profile>, String> {
    let file = match fs::File::open(dir.join("profile.json")) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("无法读取配置".into()),
    };
    let mut data = Vec::new();
    file.take(LIMIT + 1).read_to_end(&mut data).map_err(|_| "无法读取配置")?;
    if data.len() as u64 > LIMIT { return Err("配置过大".into()); }
    let profile: Profile = serde_json::from_slice(&data).map_err(|_| "配置格式无效")?;
    validate(&profile)?;
    Ok(Some(profile))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn example() -> Profile {
        Profile {
            engine: std::env::temp_dir().join("rathole.exe").to_string_lossy().into_owned(),
            remote: "relay.example.test:2333".into(),
            server_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
            mappings: vec![ProfileMapping { protocol: "tcp".into(), name: "web".into(), local_port: 8080 }],
        }
    }
    #[test]
    fn roundtrip_and_replace_without_tokens() {
        let d = tempfile::tempdir().unwrap();
        assert!(load(d.path()).unwrap().is_none());
        let mut p = example();
        save(d.path(), &p).unwrap();
        p.engine.clear(); // bundled engine selection must persist
        p.mappings[0].local_port = 5173;
        save(d.path(), &p).unwrap();
        assert_eq!(load(d.path()).unwrap().unwrap().mappings[0].local_port, 5173);
        assert!(load(d.path()).unwrap().unwrap().engine.is_empty());
        let text = fs::read_to_string(d.path().join("profile.json")).unwrap();
        assert!(!text.contains("token"));
    }
    #[test]
    fn legacy_tcp_and_udp_nonsecret_profile_roundtrip() {
        let d = tempfile::tempdir().unwrap();
        let mut legacy = serde_json::to_value(example()).unwrap();
        legacy["mappings"][0].as_object_mut().unwrap().remove("protocol");
        fs::write(d.path().join("profile.json"), legacy.to_string()).unwrap();
        let mut p = load(d.path()).unwrap().unwrap();
        assert_eq!(p.mappings[0].protocol, "tcp");
        p.mappings[0].protocol = "udp".into();
        save(d.path(), &p).unwrap();
        assert_eq!(load(d.path()).unwrap().unwrap().mappings[0].protocol, "udp");
        assert!(!fs::read_to_string(d.path().join("profile.json")).unwrap().contains("token"));
        p.mappings[0].protocol = "quic".into();
        assert!(save(d.path(), &p).is_err());
    }
    #[test]
    fn rejects_invalid_and_secret_fields() {
        let d = tempfile::tempdir().unwrap();
        let mut p = example();
        p.mappings[0].local_port = 0;
        assert!(save(d.path(), &p).is_err());
        let mut value = serde_json::to_value(example()).unwrap();
        value["mappings"][0]["token"] = serde_json::json!("secret");
        fs::write(d.path().join("profile.json"), value.to_string()).unwrap();
        assert!(load(d.path()).is_err());
        fs::write(d.path().join("profile.json"), vec![b'x'; LIMIT as usize + 1]).unwrap();
        assert!(load(d.path()).is_err());
    }
}
