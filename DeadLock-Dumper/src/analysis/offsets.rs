use std::collections::BTreeMap;

use anyhow::Result;

use log::{debug, error};

use memflow::prelude::v1::*;

use pelite::pattern;
use pelite::pattern::{Atom, save_len};
use pelite::pe64::{Pe, PeView, Rva};

use phf::{Map, phf_map};

pub type OffsetMap = BTreeMap<String, BTreeMap<String, Rva>>;

macro_rules! pattern_map {
    ($($module:ident => {
        $($name:expr => $pattern:expr $(=> $callback:expr)?),+ $(,)?
    }),+ $(,)?) => {
        $(
            mod $module {
                use super::*;

                pub(super) const PATTERNS: Map<
                    &'static str,
                    (
                        &'static [Atom],
                        Option<fn(&PeView, &mut BTreeMap<String, Rva>, Rva)>,
                    ),
                > = phf_map! {
                    $($name => ($pattern, $($callback)?)),+
                };

                pub fn offsets(view: PeView<'_>) -> BTreeMap<String, Rva> {
                    let mut map = BTreeMap::new();

                    for (&name, (pat, callback)) in &PATTERNS {
                        let mut save = vec![0; save_len(pat)];

                        if !view.scanner().finds_code(pat, &mut save) {
                            error!("outdated pattern: {}", name);

                            continue;
                        }

                        let rva = save[1];

                        map.insert(name.to_string(), rva);

                        if let Some(callback) = callback {
                            callback(&view, &mut map, rva);
                        }
                    }

                    for (name, value) in &map {
                        debug!(
                            "found \"{}\" at {:#X} ({}.dll + {:#X})",
                            name,
                            *value as u64 + view.optional_header().ImageBase,
                            stringify!($module),
                            value
                        );
                    }

                    map
                }
            }
        )+
    };
}

pattern_map! {
    // Deadlock patterns (client.dll) - Updated from UC thread page 55
    client => {
        // 48 89 35 ?? ?? ?? ?? 48 85 F6
        "dwEntityList" => pattern!("488935${'} 4885f6") => None,
        // 48 8B 35 ?? ?? ?? ?? 4C 89 B4 24 ?? ?? ?? ?? 4C 89 BC 24
        "dwGameEntitySystem" => pattern!("488b35${'} 4c89b424???? 4c89bc24") => None,
        // 48 3B 35
        "dwLocalPlayerController" => pattern!("483b35${'}") => None,
        // 49 8D 87 ?? ?? ?? ?? 4D 69 F4
        // Note: This is register-relative (LEA r8, [r15+disp]), not RIP-relative
        // So we capture the displacement directly with u4 instead of ${'}
        "dwViewMatrix" => pattern!("498d87 u4 4d69f4") => None,
        // 48 8D 3D ?? ?? ?? ?? 8B D9
        "dwCCitadelCameraManager" => pattern!("488d3d${'} 8bd9") => None,
        // 48 8B 0D ?? ?? ?? ?? 4C 8D 44 24 ?? E8 ?? ?? ?? ?? E8
        "dwGameTraceManager" => pattern!("488b0d${'} 4c8d4424? e8???? e8") => None,
        // E8 ?? ?? ?? ?? 48 85 C0 74 ?? 48 8B 40 ?? 48 8D 0D
        "fnGetCmd" => pattern!("e8${'} 4885c0 74? 488b40? 488d0d") => None,
        // E8 ?? ?? ?? ?? 48 8B 53 ?? 48 3B D5
        "fnDecodeNetworkEntities" => pattern!("e8${'} 488b53? 483bd5") => None,
        // 4C 8D 35 ?? ?? ?? ?? 0F 28 45
        "dwSchemas" => pattern!("4c8d35${'} 0f2845") => None,
        // 48 8D 05 ?? ?? ?? ?? C3 CC CC CC CC CC CC CC CC 48 8D 05 ?? ?? ?? ??
        "dwMaterialSystem" => pattern!("488d05${'} c3 cccccccccccccccc 488d05????") => None,
    },
    engine2 => {
        "dwBuildNumber" => pattern!("8905${'} 488d0d${} ff15${} 488b0d") => None,
        "dwNetworkGameClient" => pattern!("48893d${'} ff87") => None,
        "dwNetworkGameClient_clientTickCount" => pattern!("8b81u4 c3 cccccccccccccccccc 8b81${} c3 cccccccccccccccccc 83b9") => None,
        "dwNetworkGameClient_deltaTick" => pattern!("4c8db7u4 4c897c24") => None,
        "dwNetworkGameClient_isBackgroundMap" => pattern!("0fb681u4 c3 cccccccccccccccc 0fb681${} c3 cccccccccccccccc 4053") => None,
        "dwNetworkGameClient_localPlayer" => pattern!("428b94d3u4 5b 49ffe3 32c0 5b c3 cccccccccccccccc 4053") => None,
        "dwNetworkGameClient_maxClients" => pattern!("8b81u4 c3????????? 8b81[4] c3????????? 8b81") => None,
        "dwNetworkGameClient_serverTickCount" => pattern!("8b81u4 c3 cccccccccccccccccc 83b9") => None,
        "dwNetworkGameClient_signOnState" => pattern!("448b81u4 488d0d") => None,
        "dwWindowHeight" => pattern!("8b05${'} 8903") => None,
        "dwWindowWidth" => pattern!("8b05${'} 8907") => None,
    },
    input_system => {
        "dwInputSystem" => pattern!("488d05${'} c3 cccccccccccccccc 4053") => None,
    },
}

pub fn offsets<P: Process + MemoryView>(process: &mut P) -> Result<OffsetMap> {
    let mut map = BTreeMap::new();

    let modules: [(&str, fn(PeView) -> BTreeMap<String, u32>); 3] = [
        ("client.dll", client::offsets),
        ("engine2.dll", engine2::offsets),
        ("inputsystem.dll", input_system::offsets),
    ];

    for (module_name, offsets) in &modules {
        let module = process.module_by_name(module_name)?;

        let buf = process
            .read_raw(module.base, module.size as _)
            .data_part()?;

        let view = PeView::from_bytes(&buf)?;

        map.insert(module_name.to_string(), offsets(view));
    }

    Ok(map)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::Once;

    use serde_json::Value;

    use simplelog::*;

    use super::*;

    #[test]
    fn build_number() -> Result<()> {
        let mut process = setup()?;

        let engine_base = process.module_by_name("engine2.dll")?.base;

        let offset = read_offset("engine2.dll", "dwBuildNumber").unwrap();

        let build_number: u32 = process.read(engine_base + offset).data_part()?;

        debug!("build number: {}", build_number);

        Ok(())
    }

    #[test]
    fn global_vars() -> Result<()> {
        let mut process = setup()?;

        let client_base = process.module_by_name("client.dll")?.base;

        let offset = read_offset("client.dll", "dwGlobalVars").unwrap();

        let global_vars: u64 = process.read(client_base + offset).data_part()?;

        let map_name_addr = process
            .read_addr64((global_vars + 0x180).into())
            .data_part()?;

        let map_name = process.read_utf8(map_name_addr, 128).data_part()?;

        debug!("[global vars] map name: \"{}\"", map_name);

        Ok(())
    }

    #[test]
    fn local_controller() -> Result<()> {
        let mut process = setup()?;

        let client_base = process.module_by_name("client.dll")?.base;

        let local_controller_offset = read_offset("client.dll", "dwLocalPlayerController").unwrap();

        let player_name_offset =
            read_class_field("client.dll", "CBasePlayerController", "m_iszPlayerName").unwrap();

        let local_controller: u64 = process
            .read(client_base + local_controller_offset)
            .data_part()?;

        let player_name = process
            .read_utf8((local_controller + player_name_offset).into(), 128)
            .data_part()?;

        debug!("[local controller] name: \"{}\"", player_name);

        Ok(())
    }

    #[test]
    fn local_pawn() -> Result<()> {
        #[derive(Pod)]
        #[repr(C)]
        struct Vector3D {
            x: f32,
            y: f32,
            z: f32,
        }

        let mut process = setup()?;

        let client_base = process.module_by_name("client.dll")?.base;

        let local_player_pawn_offset = read_offset("client.dll", "dwLocalPlayerPawn").unwrap();

        let game_scene_node_offset =
            read_class_field("client.dll", "C_BaseEntity", "m_pGameSceneNode").unwrap();

        let origin_offset =
            read_class_field("client.dll", "CGameSceneNode", "m_vecAbsOrigin").unwrap();

        let local_player_pawn: u64 = process
            .read(client_base + local_player_pawn_offset)
            .data_part()?;

        let game_scene_node: u64 = process
            .read((local_player_pawn + game_scene_node_offset).into())
            .data_part()?;

        let origin: Vector3D = process
            .read((game_scene_node + origin_offset).into())
            .data_part()?;

        debug!(
            "[local pawn] origin: {:.2}, y: {:.2}, z: {:.2}",
            origin.x, origin.y, origin.z
        );

        Ok(())
    }

    #[test]
    fn window_size() -> Result<()> {
        let mut process = setup()?;

        let engine_base = process.module_by_name("engine2.dll")?.base;

        let window_width_offset = read_offset("engine2.dll", "dwWindowWidth").unwrap();
        let window_height_offset = read_offset("engine2.dll", "dwWindowHeight").unwrap();

        let window_width: u32 = process
            .read(engine_base + window_width_offset)
            .data_part()?;

        let window_height: u32 = process
            .read(engine_base + window_height_offset)
            .data_part()?;

        debug!("window size: {}x{}", window_width, window_height);

        Ok(())
    }

    fn setup() -> Result<IntoProcessInstanceArcBox<'static>> {
        static LOGGER: Once = Once::new();

        LOGGER.call_once(|| {
            SimpleLogger::init(LevelFilter::Trace, Config::default()).ok();
        });

        let os = memflow_native::create_os(&OsArgs::default(), LibArc::default())?;

        let process = os.into_process_by_name("project8.exe")?;

        Ok(process)
    }

    fn read_class_field(module_name: &str, class_name: &str, field_name: &str) -> Option<u64> {
        let content =
            fs::read_to_string(format!("output/{}.json", module_name.replace(".", "_"))).ok()?;

        let value: Value = serde_json::from_str(&content).ok()?;

        value
            .get(module_name)?
            .get("classes")?
            .get(class_name)?
            .get("fields")?
            .get(field_name)?
            .as_u64()
    }

    fn read_offset(module_name: &str, offset_name: &str) -> Option<u64> {
        let content = fs::read_to_string("output/offsets.json").ok()?;
        let value: Value = serde_json::from_str(&content).ok()?;

        let offset = value.get(module_name)?.get(offset_name)?;

        offset.as_u64()
    }
}
