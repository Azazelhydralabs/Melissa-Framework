//! Explicit implemented bindings. Definition-only catalog v1 is not a runtime
//! readiness source and is preserved; this small registry grants no authority.
pub fn process_routes() -> serde_json::Value {
    serde_json::json!({
        "schema_version":"melissa.process-routes/v1",
        "authority":"rust_host_policy_and_authenticated_permit",
        "implicit_backend_fallback":false,
        "routes":[
            {"tool":"process.exec","backend":"windows_appcontainer_job","input_schema":"melissa.process-exec/v2","schema_ref":"schemas/process-exec-v2.schema.json","execution_contract":crate::policy::HOST_EXECUTION_CONTRACT_VERSION,"entrypoint":"Broker::execute","disk":"monitored_explicit_host_and_grant_opt_in","cpu":"os_hard_rate_and_user_time_plus_monitored_total"},
            {"tool":"process.exec","backend":"linux_docker_readonly_tmpfs","input_schema":"melissa.container-exec/v1","schema_ref":"schemas/container-exec.schema.json","execution_contract":melissa_container_executor::EXECUTION_CONTRACT,"entrypoint":"ContainerBroker::execute","disk":"hard_allocated_tmpfs_capacity","cpu":"os_hard_rate_plus_monitored_total","host_filesystem_mounts":false},
            {"tool":"process.inspect","input_schema":"melissa.process-control/v1","schema_ref":"schemas/process-control.schema.json","entrypoint":"ProcessControlService::execute","target":"managed_task_invocation_generation_resource","separate_host_grant":true},
            {"tool":"process.cancel","input_schema":"melissa.process-control/v1","schema_ref":"schemas/process-control.schema.json","entrypoint":"ProcessControlService::execute","target":"managed_task_invocation_generation_resource","receipt":"durable_intent_then_fresh_inspect_confirms_stop","separate_host_grant":true}
        ],
        "unimplemented_catalog_tools_do_not_become_callable":true,
        "real_ai_acceptance":"not_run"
    })
}
