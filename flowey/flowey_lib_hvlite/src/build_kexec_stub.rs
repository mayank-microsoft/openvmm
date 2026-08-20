// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Build the `kexec_stub` flat binary (x86_64 only).
//!
//! Produces the bare-metal `minimal_rt` stub used by guest-driven kexec
//! servicing to boot an uncompressed vmlinux. The stub is built as an ELF and
//! then converted to a raw flat binary via `objcopy -O binary`, which is what
//! `underhill_core` embeds via `include_bytes!` (wired through the
//! `OPENVMM_KEXEC_STUB_BIN` environment variable).

use crate::run_cargo_build::BuildProfile;
use flowey::node::prelude::*;

flowey_request! {
    pub struct Request {
        /// Receives the path to the built `kexec_stub` flat binary.
        pub kexec_stub_bin: WriteVar<PathBuf>,
    }
}

new_flow_node!(struct Node);

impl FlowNode for Node {
    type Request = Request;

    fn imports(ctx: &mut ImportCtx<'_>) {
        ctx.import::<crate::run_cargo_build::Node>();
        ctx.import::<flowey_lib_common::install_dist_pkg::Node>();
    }

    fn emit(requests: Vec<Self::Request>, ctx: &mut NodeCtx<'_>) -> anyhow::Result<()> {
        let outvars: Vec<_> = requests.into_iter().map(|r| r.kexec_stub_bin).collect();
        if outvars.is_empty() {
            return Ok(());
        }

        // The stub is x86_64-only; build it for the bare-metal minimal_rt target.
        let target = target_lexicon::Triple {
            architecture: target_lexicon::Architecture::X86_64,
            operating_system: target_lexicon::OperatingSystem::None_,
            environment: target_lexicon::Environment::Unknown,
            vendor: target_lexicon::Vendor::Custom(target_lexicon::CustomVendor::Static(
                "minimal_rt",
            )),
            binary_format: target_lexicon::BinaryFormat::Unknown,
        };

        let mut pre_build_deps = Vec::new();

        if matches!(
            ctx.platform(),
            FlowPlatform::Linux(FlowPlatformLinuxDistro::Ubuntu)
        ) {
            pre_build_deps.push(ctx.reqv(|v| {
                flowey_lib_common::install_dist_pkg::Request::Install {
                    package_names: vec!["build-essential".into(), "binutils".into()],
                    done: v,
                }
            }));
        }

        let output = ctx.reqv(|v| crate::run_cargo_build::Request {
            crate_name: "kexec_stub".into(),
            out_name: "kexec_stub".into(),
            crate_type: flowey_lib_common::run_cargo_build::CargoCrateType::Bin,
            profile: BuildProfile::BootRelease,
            features: Default::default(),
            target,
            no_split_dbg_info: true,
            extra_env: Some(ReadVar::from_static(
                [("RUSTC_BOOTSTRAP".to_string(), "1".to_string())]
                    .into_iter()
                    .collect(),
            )),
            pre_build_deps,
            output: v,
        });

        ctx.emit_rust_step("objcopy kexec_stub to flat binary", |ctx| {
            let outvars = outvars.claim(ctx);
            let output = output.claim(ctx);
            move |rt| {
                let elf = match rt.read(output) {
                    crate::run_cargo_build::CargoBuildOutput::ElfBin { bin, .. } => bin,
                    _ => unreachable!(),
                };
                let flat = rt.sh.current_dir().join("kexec_stub.bin");
                flowey::shell_cmd!(rt, "objcopy -O binary {elf} {flat}").run()?;
                for var in outvars {
                    rt.write(var, &flat);
                }
                Ok(())
            }
        });

        Ok(())
    }
}
