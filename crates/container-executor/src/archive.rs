use crate::*;
pub(crate) fn safe_name(name: &str) -> ExecutorResult {
    if name.is_empty()
        || name.len() > 100
        || name.contains(['\0', '\\', ':'])
        || name.starts_with('/')
        || name
            .split('/')
            .any(|p| p.is_empty() || p == "." || p == "..")
        || name.split('/').count() > 16
    {
        return Err(ExecutorError::Invalid(
            "unsafe or unsupported snapshot path".into(),
        ));
    }
    Ok(())
}
fn octal(dest: &mut [u8], value: u64) {
    let value = format!("{value:0width$o}", width = dest.len() - 1);
    dest[..value.len()].copy_from_slice(value.as_bytes());
}
pub(crate) fn pack(snapshot: &Snapshot) -> ExecutorResult<Vec<u8>> {
    snapshot.validate(MAX_CAPTURE)?;
    let mut tar = Vec::new();
    for (name, data) in &snapshot.files {
        let mut header = [0u8; 512];
        header[..name.len()].copy_from_slice(name.as_bytes());
        octal(&mut header[100..108], 0o644);
        octal(&mut header[108..116], 65534);
        octal(&mut header[116..124], 65534);
        octal(&mut header[124..136], data.len() as u64);
        octal(&mut header[136..148], 0);
        header[148..156].fill(b' ');
        header[156] = b'0';
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        let sum = header.iter().map(|b| u64::from(*b)).sum();
        octal(&mut header[148..155], sum);
        header[155] = b' ';
        tar.extend(header);
        tar.extend(data);
        tar.resize(tar.len().div_ceil(512) * 512, 0);
    }
    tar.resize(tar.len() + 1024, 0);
    Ok(tar)
}
