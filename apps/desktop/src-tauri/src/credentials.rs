//! Explicit opt-in, current-user DPAPI encrypted profile. No plaintext fallback.
#[cfg(windows)]
mod windows {
    use crate::{build_config, StartRequest};
    use std::{fs, io::{Read, Write}, path::Path, ptr, slice};
    use tempfile::NamedTempFile;
    use windows_sys::Win32::{Foundation::LocalFree, Security::Cryptography::{CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData}};
    use zeroize::{Zeroize, Zeroizing};

    const LIMIT: usize = 256 * 1024;

    struct Blob(CRYPT_INTEGER_BLOB);
    impl Drop for Blob {
        fn drop(&mut self) {
            if !self.0.pbData.is_null() {
                // SAFETY: DPAPI owns this allocated output buffer until LocalFree.
                unsafe {
                    slice::from_raw_parts_mut(self.0.pbData, self.0.cbData as usize).zeroize();
                    LocalFree(self.0.pbData.cast());
                }
            }
        }
    }

    fn transform(data: &[u8], protect: bool) -> Result<Zeroizing<Vec<u8>>, String> {
        if data.is_empty() || data.len() > LIMIT { return Err("凭据数据大小无效".into()); }
        let mut input = Zeroizing::new(data.to_vec());
        let input_blob = CRYPT_INTEGER_BLOB { cbData: input.len() as u32, pbData: input.as_mut_ptr() };
        let mut output = Blob(CRYPT_INTEGER_BLOB { cbData: 0, pbData: ptr::null_mut() });
        // SAFETY: input lives throughout the call, output initialized, no optional pointers,
        // no machine-wide scope or interactive prompt. The output allocation is owned by Blob.
        let ok = unsafe {
            if protect {
                CryptProtectData(&input_blob, ptr::null(), ptr::null(), ptr::null(), ptr::null(), CRYPTPROTECT_UI_FORBIDDEN, &mut output.0)
            } else {
                CryptUnprotectData(&input_blob, ptr::null_mut(), ptr::null(), ptr::null(), ptr::null(), CRYPTPROTECT_UI_FORBIDDEN, &mut output.0)
            }
        };
        if ok == 0 || output.0.pbData.is_null() || output.0.cbData as usize > LIMIT {
            return Err("Windows 凭据保护操作失败".into());
        }
        Ok(Zeroizing::new(unsafe { slice::from_raw_parts(output.0.pbData, output.0.cbData as usize) }.to_vec()))
    }

    fn validate(request: &StartRequest) -> Result<(), String> {
        if request.engine.len() > 4096 || (!request.engine.is_empty() && !Path::new(&request.engine).is_absolute()) {
            return Err("自定义引擎路径须为绝对路径，留空使用内置引擎".into());
        }
        let _config = Zeroizing::new(build_config(request)?);
        Ok(())
    }

    pub fn save(dir: &Path, request: &StartRequest) -> Result<(), String> {
        validate(request)?;
        let data = Zeroizing::new(serde_json::to_vec(request).map_err(|_| "凭据序列化失败")?);
        let encrypted = transform(&data, true)?;
        fs::create_dir_all(dir).map_err(|_| "无法创建凭据目录")?;
        let mut file = NamedTempFile::new_in(dir).map_err(|_| "无法创建凭据临时文件")?;
        file.write_all(&encrypted).and_then(|_| file.as_file().sync_all()).map_err(|_| "无法写入加密凭据")?;
        file.persist(dir.join("protected-profile.bin")).map_err(|_| "无法替换加密凭据")?;
        Ok(())
    }

    pub fn load(dir: &Path) -> Result<Option<StartRequest>, String> {
        let file = match fs::File::open(dir.join("protected-profile.bin")) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err("无法读取加密凭据".into()),
        };
        let mut encrypted = Vec::new();
        file.take((LIMIT + 1) as u64).read_to_end(&mut encrypted).map_err(|_| "无法读取加密凭据")?;
        let data = transform(&encrypted, false)?;
        let request: StartRequest = serde_json::from_slice(&data).map_err(|_| "凭据格式无效")?;
        validate(&request)?;
        Ok(Some(request))
    }

    pub fn forget(dir: &Path) -> Result<(), String> {
        match fs::remove_file(dir.join("protected-profile.bin")) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err("无法删除已保存凭据".into()),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::Mapping;
        #[test]
        fn dpapi_roundtrip_replace_and_forget() {
            let dir = tempfile::tempdir().unwrap();
            let token = "a".repeat(32);
            let mut request = StartRequest {
                engine: dir.path().join("rathole.exe").to_string_lossy().into_owned(),
                remote: "relay.example.test:2333".into(),
                server_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
                mappings: vec![Mapping { name: "web".into(), local_port: 8080, token: token.clone() }],
            };
            assert!(load(dir.path()).unwrap().is_none());
            save(dir.path(), &request).unwrap();
            let file = dir.path().join("protected-profile.bin");
            let bytes = fs::read(&file).unwrap();
            assert!(!bytes.windows(token.len()).any(|w| w == token.as_bytes()));
            assert_eq!(load(dir.path()).unwrap().unwrap().mappings[0].token, token);
            request.mappings[0].local_port = 5173;
            save(dir.path(), &request).unwrap();
            assert_eq!(load(dir.path()).unwrap().unwrap().mappings[0].local_port, 5173);
            fs::write(&file, b"not DPAPI ciphertext").unwrap();
            assert!(load(dir.path()).is_err());
            forget(dir.path()).unwrap();
            forget(dir.path()).unwrap();
            assert!(load(dir.path()).unwrap().is_none());
        }
    }
}

#[cfg(windows)]
pub use windows::{save, load, forget};
#[cfg(not(windows))]
pub fn save(_: &std::path::Path, _: &crate::StartRequest) -> Result<(), String> { Err("仅 Windows 支持凭据保护".into()) }
#[cfg(not(windows))]
pub fn load(_: &std::path::Path) -> Result<Option<crate::StartRequest>, String> { Err("仅 Windows 支持凭据保护".into()) }
#[cfg(not(windows))]
pub fn forget(_: &std::path::Path) -> Result<(), String> { Err("仅 Windows 支持凭据保护".into()) }
