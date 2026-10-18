use std::{env, fs, io::Write, path::Path};

use base64::Engine;
use flate2::{Compression, write::GzEncoder};

fn main() {
    sedge_gen::build("templates");
    println!(
        "cargo::metadata=templates={}/templates",
        env!("CARGO_MANIFEST_DIR")
    );

    let out_dir = env::var_os("OUT_DIR").expect("OUT_DIR");
    let out_dir = Path::new(&out_dir);
    for (name, path) in [
        ("grund.css", "assets/grund.css"),
        ("grund.js", "assets/grund.js"),
        ("mark.svg", "assets/mark.svg"),
        ("uplot.js", "assets/vendor/uplot-1.6.32.min.js"),
        ("telemetry.js", "assets/telemetry.js"),
    ] {
        println!("cargo:rerun-if-changed={path}");
        let body = fs::read(path).expect("read static asset");
        precompress(name, &body, out_dir);
    }
    precompress("sedx.js", sedx::JS.as_bytes(), out_dir);
    embed_image_logos(out_dir);
}

fn embed_image_logos(out_dir: &Path) {
    let table = "assets/logos/sources.tsv";
    println!("cargo:rerun-if-changed={table}");
    let notice_path = "assets/logos/NOTICE.txt";
    println!("cargo:rerun-if-changed={notice_path}");
    let mut notices = fs::read_to_string(notice_path).expect("read product logo notices");
    let sources = fs::read_to_string(table).expect("read logo clearance table");
    let mut generated = String::from("const IMAGE_LOGOS: &[(&str, &str, &str, &str, bool)] = &[\n");
    for line in sources.lines().skip(1) {
        let columns: Vec<_> = line.split('\t').collect();
        assert_eq!(columns.len(), 8, "logo source table has eight columns");
        match columns[5] {
            "allow" | "Kasper accepted risk 2026-10-17" => {}
            "neutral" => continue,
            decision => panic!("unknown logo decision: {decision}"),
        }
        let key = columns[0];
        let path = format!("assets/logos/{key}.svg");
        println!("cargo:rerun-if-changed={path}");
        let svg = fs::read(&path).expect("read original upstream logo");
        let encoded = base64::engine::general_purpose::STANDARD.encode(svg);
        let wide = match columns[7] {
            "wide" => true,
            "square" => false,
            layout => panic!("unknown logo layout: {layout}"),
        };
        let width = if wide { 72 } else { 44 };
        let symbol = format!(
            "<symbol id=\"img-{key}\" viewBox=\"0 0 {width} 44\"><image width=\"{width}\" height=\"44\" preserveAspectRatio=\"xMidYMid meet\" href=\"data:image/svg+xml;base64,{encoded}\"/></symbol>"
        );
        generated.push_str(&format!(
            "({key:?}, {:?}, {symbol:?}, {:?}, {wide}),\n",
            columns[4], columns[6]
        ));
        notices.push('\n');
        for (label, value) in [
            ("", columns[1]),
            ("", columns[6]),
            ("Source: ", columns[2]),
            ("Policy: ", columns[3]),
            ("Decision: ", columns[5]),
        ] {
            notices.push_str(label);
            notices.push_str(value);
            notices.push('\n');
        }
    }
    generated.push_str("];\n");
    fs::write(out_dir.join("image_logos.rs"), generated).expect("write embedded logo symbols");
    fs::write(out_dir.join("logo_notices.txt"), notices).expect("write product logo notices");
}

fn precompress(name: &str, body: &[u8], out_dir: &Path) {
    let mut br = Vec::new();
    {
        let mut encoder = brotli::CompressorWriter::new(&mut br, 4096, 11, 22);
        encoder.write_all(body).expect("compress embedded asset");
    }
    fs::write(
        out_dir.join(format!("{name}.br")),
        if br.len() * 10 <= body.len() * 9 {
            br.as_slice()
        } else {
            &[]
        },
    )
    .expect("write brotli asset");

    let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
    encoder.write_all(body).expect("compress embedded asset");
    let gzip = encoder.finish().expect("finish gzip asset");
    fs::write(
        out_dir.join(format!("{name}.gz")),
        if gzip.len() * 10 <= body.len() * 9 {
            gzip.as_slice()
        } else {
            &[]
        },
    )
    .expect("write gzip asset");
}
