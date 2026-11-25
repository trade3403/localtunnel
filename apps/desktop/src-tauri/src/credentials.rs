//! Explicit opt-in, current-user DPAPI encrypted profile. No plaintext fallback.
#[cfg(windows)]
mod windows {
    use crate::{build_config, StartRequest};
    use std::{fs, io::{Read, Write}, path::Path, ptr, slice};
    use tempfile::NamedTempFile;
    use windows_sys::Win32::{Foundation::LocalFree, Security::Cryptography::{CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CRYPTPROTECT_LOCAL_MACHINE, CryptProtectData, CryptUnprotectData}};
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

    fn transform_scoped(data: &[u8], protect: bool, machine: bool) -> Result<Zeroizing<Vec<u8>>, String> {
        if data.is_empty() || data.len() > LIMIT { return Err("凭据数据大小无效".into()); }
        let mut input = Zeroizing::new(data.to_vec());
        let input_blob = CRYPT_INTEGER_BLOB { cbData: input.len() as u32, pbData: input.as_mut_ptr() };
        let mut output = Blob(CRYPT_INTEGER_BLOB { cbData: 0, pbData: ptr::null_mut() });
        // SAFETY: input lives throughout the call, output initialized, no optional pointers,
        // no interactive prompt. Only explicit service provisioning uses machine scope.
        let ok = unsafe {
            if protect {
                CryptProtectData(&input_blob, ptr::null(), ptr::null(), ptr::null(), ptr::null(), CRYPTPROTECT_UI_FORBIDDEN | if machine { CRYPTPROTECT_LOCAL_MACHINE } else { 0 }, &mut output.0)
            } else {
                CryptUnprotectData(&input_blob, ptr::null_mut(), ptr::null(), ptr::null(), ptr::null(), CRYPTPROTECT_UI_FORBIDDEN, &mut output.0)
            }
        };
        if ok == 0 || output.0.pbData.is_null() || output.0.cbData as usize > LIMIT {
            return Err("Windows 凭据保护操作失败".into());
        }
        Ok(Zeroizing::new(unsafe { slice::from_raw_parts(output.0.pbData, output.0.cbData as usize) }.to_vec()))
    }

    fn transform(data: &[u8], protect: bool) -> Result<Zeroizing<Vec<u8>>, String> {
        transform_scoped(data, protect, false)
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

    // Service credentials live in an administrator-provisioned, service-SID
    // restricted directory. The blob is separately sealed with machine DPAPI.
    // Machine protection alone is NOT account isolation; the ACL is mandatory.
    // Caller must first provision a protected deployment directory and verify its
    // ACL. No overwrite: credential rotation requires a separate stopped-service
    // operation. Never pass plaintext profile data in argv or environment.
    pub fn seal_service(dir: &Path, mut source: impl Read) -> Result<(), String> {
        let mut data = Zeroizing::new(Vec::new());
        source.by_ref().take((LIMIT + 1) as u64).read_to_end(&mut data)
            .map_err(|_| "无法读取服务配置")?;
        if data.is_empty() || data.len() > LIMIT { return Err("服务配置大小无效".into()); }
        let request: StartRequest = serde_json::from_slice(&data).map_err(|_| "服务配置格式无效")?;
        if !request.engine.is_empty() { return Err("服务只能使用内置引擎".into()); }
        validate(&request)?;
        let encrypted = transform_scoped(&data, true, true)?;
        let mut file = NamedTempFile::new_in(dir).map_err(|_| "无法创建服务凭据文件")?;
        file.write_all(&encrypted).and_then(|_| file.as_file().sync_all())
            .map_err(|_| "无法写入服务凭据")?;
        file.persist_noclobber(dir.join("service-profile.bin"))
            .map_err(|_| "服务凭据已存在或无法保存")?;
        Ok(())
    }

    // Caller holds the exact SCM service stopped and disabled. Prepare
    // an encrypted candidate with a protected ACL before replacing old data.
    pub fn replace_service(dir: &Path, name: &str, request: &StartRequest) -> Result<(), String> {
        if !request.engine.is_empty() { return Err("服务只能使用内置引擎".into()); }
        validate(request)?;
        let data = Zeroizing::new(serde_json::to_vec(request).map_err(|_| "服务凭据序列化失败")?);
        let encrypted = transform_scoped(&data, true, true)?;
        let decoded = transform(&encrypted, false)?;
        if decoded.as_slice() != data.as_slice() { return Err("服务凭据加密校验失败".into()); }
        let mut file = NamedTempFile::new_in(dir).map_err(|_| "无法创建服务凭据候选文件")?;
        file.write_all(&encrypted).and_then(|_| file.as_file().sync_all())
            .map_err(|_| "无法同步服务凭据候选文件")?;
        let sid = crate::service_acl::service_sid(name)?;
        crate::service_provision::set_acl(file.path(), false, Some((&sid, false)))?;
        file.persist(dir.join("service-profile.bin"))
            .map_err(|_| "无法原子替换服务凭据")?;
        crate::service_acl::validate(dir, name, true)?;
        let saved = load_service(dir)?;
        let saved_bytes = Zeroizing::new(serde_json::to_vec(&saved).map_err(|_| "服务凭据回读失败")?);
        if saved_bytes.as_slice() != data.as_slice() { return Err("服务凭据回读不匹配".into()); }
        Ok(())
    }

    pub fn load_service(dir: &Path) -> Result<StartRequest, String> {
        let file = fs::File::open(dir.join("service-profile.bin")).map_err(|_| "服务凭据缺失")?;
        let mut encrypted = Vec::new();
        file.take((LIMIT + 1) as u64).read_to_end(&mut encrypted).map_err(|_| "无法读取服务凭据")?;
        let data = transform(&encrypted, false)?;
        let request: StartRequest = serde_json::from_slice(&data).map_err(|_| "服务凭据格式无效")?;
        if !request.engine.is_empty() { return Err("服务只能使用内置引擎".into()); }
        validate(&request)?;
        Ok(request)
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
        fn machine_service_seal_is_validated_and_never_overwrites() {
            let dir = tempfile::tempdir().unwrap();
            let token = "b".repeat(32);
            let mut request = StartRequest {
                engine: "C:\\untrusted.exe".into(),
                remote: "relay.example.test:2333".into(),
                server_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
                mappings: vec![Mapping { name: "web".into(), local_port: 8080, token: token.clone() }],
            };
            assert!(seal_service(dir.path(), serde_json::to_vec(&request).unwrap().as_slice()).is_err());
            assert!(!dir.path().join("service-profile.bin").exists());
            request.engine.clear();
            let json = serde_json::to_vec(&request).unwrap();
            seal_service(dir.path(), json.as_slice()).unwrap();
            let file = dir.path().join("service-profile.bin");
            let original = fs::read(&file).unwrap();
            assert!(!original.windows(token.len()).any(|w| w == token.as_bytes()));
            assert_eq!(load_service(dir.path()).unwrap().mappings[0].token, token);
            assert!(seal_service(dir.path(), json.as_slice()).is_err());
            assert_eq!(fs::read(&file).unwrap(), original);
            fs::write(file, b"not ciphertext").unwrap();
            assert!(load_service(dir.path()).is_err());
        }

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
pub use windows::{save, load, forget, load_service, seal_service, replace_service};
#[cfg(not(windows))]
pub fn save(_: &std::path::Path, _: &crate::StartRequest) -> Result<(), String> { Err("仅 Windows 支持凭据保护".into()) }
#[cfg(not(windows))]
pub fn load(_: &std::path::Path) -> Result<Option<crate::StartRequest>, String> { Err("仅 Windows 支持凭据保护".into()) }
#[cfg(not(windows))]
pub fn forget(_: &std::path::Path) -> Result<(), String> { Err("仅 Windows 支持凭据保护".into()) }
