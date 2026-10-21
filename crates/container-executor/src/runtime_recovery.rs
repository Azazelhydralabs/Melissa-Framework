// Included in the pinned Docker runtime; no second engine/client implementation.
pub(crate) fn recover_owned(id:&str,image:&str)->ExecutorResult<crate::recovery::RecoveryReport> {
    let hex=|s:&str,n:usize|s.len()==n && s.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b));
    if !hex(id,64) || !image.strip_prefix("sha256:").is_some_and(|s|hex(s,64)) {
        return Err(fail("recovery requires exact full container/image digests"));
    }
    let docker=Docker::new()?;
    let (status,value)=docker.get(&format!("/containers/{id}/json"))?;
    let mut report=crate::recovery::RecoveryReport{container_id:id.into(),image_id:image.into(),docker_client_identity:docker.client_identity.clone(),removed:false,already_absent:false,previously_running:false,invocation_outcome_known:false};
    if status==404 {report.already_absent=true;return Ok(report);}
    let nonce=value["Config"]["Labels"]["melissa.code03.nonce"].as_str().unwrap_or("");
    if status!=200 || value["Id"]!=id || value["Image"]!=image || !hex(nonce,32)
        || value["Name"]!=format!("/melissa-code03-{nonce}")
        || value["Config"]["Labels"]["melissa.code03.contract"]!=EXECUTION_CONTRACT {
        return Err(fail("recovery resource identity/nonce/image/contract mismatch"));
    }
    report.previously_running=value["State"]["Running"].as_bool().ok_or_else(||fail("recovery container state unavailable"))?;
    docker.checked(&strings(&["rm","--force",id]),None,CONTROL_LIMIT)?;
    let (after,_)=docker.get(&format!("/containers/{id}/json"))?;
    if after!=404 {return Err(fail("owned recovery removal not confirmed"));}
    report.removed=true;Ok(report)
}
