//! FugaWrap on Tauri. The UI (src/renderer) is shared with the Electron build;
//! src/renderer/bridge.js maps its `window.fugawrap` API onto these commands.

mod dnsmode;
mod doh;
#[cfg(target_os = "macos")]
mod mac;
mod probe;
mod proxy;
#[cfg(windows)]
mod ps;
mod settings;
mod sysproxy;
mod tls;

use proxy::{FragProxy, Learned, LogFn, ResolveFn, StatsView};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tauri::{AppHandle, Emitter, Manager, RunEvent, State};
use tls::{describe, Strategy};

struct AppState {
    settings: settings::Store,
    sysproxy: sysproxy::SysProxy,
    proxy: Mutex<Option<FragProxy>>,
    learned_path: PathBuf,
}

// ---------------------------------------------------------------- learned splits

/// Splits the proxy learned per host, kept across sessions. Only valid for the
/// main strategy they were learned with.
#[derive(Serialize, Deserialize, Default)]
struct LearnedFile {
    strategy: Option<Strategy>,
    hosts: Learned,
}

fn load_learned(path: &Path, strategy: Option<&Strategy>) -> Learned {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|t| serde_json::from_str::<LearnedFile>(&t).ok())
        .filter(|f| f.strategy.as_ref() == strategy)
        .map(|f| f.hosts)
        .unwrap_or_default()
}

fn save_learned(path: &Path, strategy: Option<&Strategy>, hosts: &Learned) {
    let file = LearnedFile { strategy: strategy.cloned(), hosts: hosts.clone() };
    if let Ok(json) = serde_json::to_string_pretty(&file) {
        let _ = std::fs::write(path, json);
    }
}

/// Hosts the check found blocked by name, with the split the proxy should start with.
fn learned_from_check(report: &probe::Report, strategy: Option<&Strategy>) -> Learned {
    report
        .targets
        .iter()
        .filter(|t| t.kind == "sni")
        .filter_map(|t| Some((format!("{}:443", t.host), proxy::plan_for_check(strategy, t.strategy.as_ref()?)?)))
        .map(|(k, plan)| (k, Some(plan)))
        .collect()
}

type CmdResult<T> = Result<T, String>;

fn log(app: &AppHandle, line: impl Into<String>) {
    let _ = app.emit("log", line.into());
}

/// Run blocking work off the async runtime's worker threads.
async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> CmdResult<T> {
    tauri::async_runtime::spawn_blocking(f).await.map_err(|e| e.to_string())
}

// ---------------------------------------------------------------- settings

#[tauri::command]
fn get_settings(state: State<'_, AppState>) -> Value {
    json!({ "settings": state.settings.get(), "providers": dnsmode::providers_json() })
}

#[tauri::command]
fn set_targets(state: State<'_, AppState>, targets: Vec<String>) -> CmdResult<settings::Settings> {
    let clean = settings::clean_targets(&targets);
    if clean.is_empty() {
        return Err("Add at least one host name".into());
    }
    state.settings.update(|s| s.targets = clean)
}

// ---------------------------------------------------------------- check

#[tauri::command]
async fn diagnose(app: AppHandle) -> CmdResult<probe::Report> {
    let state = app.state::<AppState>();
    let targets = state.settings.get().targets;
    // While Optimize runs, also test the path through it.
    let via_proxy = state.proxy.lock().unwrap().as_ref().map(FragProxy::port);
    let a = app.clone();
    let report = blocking(move || probe::diagnose(&targets, via_proxy, |r| { let _ = a.emit("diagnose:progress", r); })).await?;
    // Let Optimize start blocked hosts with the split straight away.
    let strategy = state.settings.get().strategy;
    let seeds = learned_from_check(&report, strategy.as_ref());
    match state.proxy.lock().unwrap().as_ref() {
        Some(p) => p.learn(seeds),
        None if !seeds.is_empty() => {
            let mut hosts = load_learned(&state.learned_path, strategy.as_ref());
            hosts.extend(seeds);
            save_learned(&state.learned_path, strategy.as_ref(), &hosts);
        }
        None => {}
    }
    Ok(report)
}

// ---------------------------------------------------------------- dns

#[tauri::command]
async fn dns_status() -> CmdResult<dnsmode::DnsStatus> {
    blocking(dnsmode::status).await
}

#[tauri::command]
async fn dns_set(app: AppHandle, provider: String) -> CmdResult<dnsmode::DnsStatus> {
    let p = provider.clone();
    let r = blocking(move || dnsmode::set(&p)).await??;
    app.state::<AppState>().settings.update(|s| s.provider = provider)?;
    Ok(r)
}

#[tauri::command]
async fn dns_restore() -> CmdResult<dnsmode::DnsStatus> {
    blocking(dnsmode::restore).await?
}

// ---------------------------------------------------------------- optimize

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OptimizeStatus {
    running: bool,
    port: Option<u16>,
    strategy: Option<Strategy>,
    strategy_text: String,
    stats: Option<StatsView>,
}

fn optimize_status_of(state: &AppState) -> OptimizeStatus {
    let strategy = state.settings.get().strategy;
    let proxy = state.proxy.lock().unwrap();
    OptimizeStatus {
        running: proxy.is_some(),
        port: proxy.as_ref().map(FragProxy::port),
        strategy_text: describe(strategy.as_ref()),
        strategy,
        stats: proxy.as_ref().map(FragProxy::stats),
    }
}

fn start_optimize(app: &AppHandle, state: &AppState) -> CmdResult<()> {
    let mut slot = state.proxy.lock().unwrap();
    if slot.is_some() {
        return Ok(());
    }
    let s = state.settings.get();
    let resolver = Arc::new(doh::Resolver::new(Duration::from_secs(300)));
    let resolve: ResolveFn = Arc::new(move |host| resolver.resolve(host));
    let log_app = app.clone();
    let on_log: LogFn = Arc::new(move |line| log(&log_app, line));
    let p = FragProxy::start(s.proxy_port, resolve, s.strategy.clone(), on_log).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AddrInUse {
            format!("Port {} is already in use", s.proxy_port)
        } else {
            e.to_string()
        }
    })?;
    p.learn(load_learned(&state.learned_path, s.strategy.as_ref()));
    let path = state.learned_path.clone();
    p.on_learn(Arc::new(move |strategy, hosts| save_learned(&path, strategy, hosts)));
    if let Err(e) = state.sysproxy.enable(p.port()) {
        p.stop();
        let _ = state.sysproxy.restore();
        return Err(e);
    }
    log(app, format!("Optimize on: 127.0.0.1:{}, {}", p.port(), describe(s.strategy.as_ref())));
    *slot = Some(p);
    Ok(())
}

/// Restore the system proxy first, then shut the proxy down. Never leave the
/// system proxy pointing at a dead port.
fn stop_optimize(app: &AppHandle, state: &AppState) -> CmdResult<()> {
    let restored = state.sysproxy.restore();
    if let Some(p) = state.proxy.lock().unwrap().take() {
        p.stop();
        log(app, "Optimize off, system proxy restored");
    }
    restored.map(|_| ())
}

#[tauri::command]
fn optimize_status(state: State<'_, AppState>) -> OptimizeStatus {
    optimize_status_of(&state)
}

#[tauri::command]
async fn optimize_start(app: AppHandle) -> CmdResult<OptimizeStatus> {
    let a = app.clone();
    blocking(move || start_optimize(&a, &a.state::<AppState>())).await??;
    Ok(optimize_status_of(&app.state::<AppState>()))
}

#[tauri::command]
async fn optimize_stop(app: AppHandle) -> CmdResult<OptimizeStatus> {
    let a = app.clone();
    blocking(move || stop_optimize(&a, &a.state::<AppState>())).await??;
    Ok(optimize_status_of(&app.state::<AppState>()))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MeasureReply {
    #[serde(flatten)]
    measure: probe::Measure,
    strategy_text: String,
    status: OptimizeStatus,
}

#[tauri::command]
async fn optimize_measure(app: AppHandle, host: Option<String>) -> CmdResult<MeasureReply> {
    let state = app.state::<AppState>();
    let host = host.unwrap_or_else(|| state.settings.get().targets.first().cloned().unwrap_or_default());
    let measure = blocking(move || probe::measure_strategy(&host)).await?;
    if let Some(s) = &measure.strategy {
        state.settings.update(|st| st.strategy = Some(s.clone()))?;
        if let Some(p) = state.proxy.lock().unwrap().as_ref() {
            p.set_strategy(Some(s.clone()));
        }
    }
    Ok(MeasureReply {
        strategy_text: describe(measure.strategy.as_ref()),
        measure,
        status: optimize_status_of(&state),
    })
}

// ---------------------------------------------------------------- app

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            if let Some(w) = app.get_webview_window("main") {
                let _ = w.unminimize();
                let _ = w.set_focus();
            }
        }))
        .setup(|app| {
            // Keyed by the bundle identifier, so renaming the app keeps the same folder.
            let dir = app.path().app_config_dir()?;
            std::fs::create_dir_all(&dir)?;
            let settings = settings::Store::load(dir.join("settings.json"));
            let sysproxy = sysproxy::SysProxy::new(dir.join("sysproxy-backup.json"));
            match sysproxy.recover(settings.get().proxy_port) {
                Ok(Some(msg)) => eprintln!("{msg}"),
                Ok(None) => {}
                Err(e) => eprintln!("proxy recovery failed: {e}"),
            }
            let learned_path = dir.join("proxy-learned.json");
            app.manage(AppState { settings, sysproxy, proxy: Mutex::new(None), learned_path });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_settings,
            set_targets,
            diagnose,
            dns_status,
            dns_set,
            dns_restore,
            optimize_status,
            optimize_start,
            optimize_stop,
            optimize_measure,
        ])
        .build(tauri::generate_context!())
        .expect("error while building FugaWrap")
        .run(|app, event| {
            if let RunEvent::Exit = event {
                if let Some(state) = app.try_state::<AppState>() {
                    let _ = stop_optimize(app, &state);
                }
            }
        });
}
