//! Drive the setup UI and save a PNG, without firmware or a browser.
//!
//! cargo run --manifest-path ui-harness/Cargo.toml --example shot -- \
//!     [--scenario NAME] [--size WxH] [--steps "STEP ..."] OUT.png
//!
//! Steps run in order: key names (Enter, Tab, BackTab, ArrowDown, F8, a, ...),
//! `click:X,Y`, `pointer:X,Y`, `scroll:N` and `wait:MS` (virtual time).
//! The final UI state is printed as JSON.
use crabefi_ui_harness::Playground;
use std::{fs::File, io::BufWriter, process::ExitCode};

fn pair(value: &str, separator: char) -> Option<(u32, u32)> {
    let (a, b) = value.split_once(separator)?;
    Some((a.parse().ok()?, b.parse().ok()?))
}

fn step(host: &mut Playground, step: &str) -> Result<(), String> {
    let (verb, arg) = step.split_once(':').unwrap_or((step, ""));
    match verb {
        "click" => {
            let (x, y) = pair(arg, ',').ok_or("click needs X,Y")?;
            host.click(x, y)?;
        }
        "pointer" => {
            let (x, y) = pair(arg, ',').ok_or("pointer needs X,Y")?;
            host.pointer(x as i32, y as i32);
        }
        "scroll" => host.scroll(arg.parse().map_err(|_| "scroll needs N")?)?,
        "wait" => {
            let ms: u32 = arg.parse().map_err(|_| "wait needs MS")?;
            host.advance(ms);
            return Ok(());
        }
        _ => host.key(step)?,
    }
    host.advance(0);
    Ok(())
}

fn run() -> Result<(), String> {
    let mut scenario = String::from("normal");
    let (mut width, mut height) = (1024, 768);
    let mut steps = String::new();
    let mut out = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut value = || args.next().ok_or(format!("{arg} needs a value"));
        match arg.as_str() {
            "--scenario" => scenario = value()?,
            "--size" => (width, height) = pair(&value()?, 'x').ok_or("--size needs WxH")?,
            "--steps" => steps = value()?,
            _ if out.is_none() && !arg.starts_with('-') => out = Some(arg),
            _ => return Err(format!("unexpected argument {arg}")),
        }
    }
    let out = out.ok_or("missing OUT.png")?;
    let mut host = Playground::new(width, height, &scenario)?;
    for s in steps.split_whitespace() {
        step(&mut host, s).map_err(|e| format!("{s}: {e}"))?;
    }
    let file = File::create(&out).map_err(|e| format!("{out}: {e}"))?;
    let mut encoder = png::Encoder::new(BufWriter::new(file), width, height);
    encoder.set_color(png::ColorType::Rgba);
    encoder.set_depth(png::BitDepth::Eight);
    encoder
        .write_header()
        .and_then(|mut writer| writer.write_image_data(&host.rgba()))
        .map_err(|e| format!("{out}: {e}"))?;
    println!("{}", host.state_json());
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("shot: {error}");
            ExitCode::FAILURE
        }
    }
}
