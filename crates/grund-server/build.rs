use std::{env, fs, io::Write, path::Path};

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
    let sources = fs::read_to_string(table).expect("read logo clearance table");
    let mut generated = String::from("const IMAGE_LOGOS: &[(&str, &str, &str)] = &[\n");
    for line in sources.lines().skip(1) {
        let columns: Vec<_> = line.split('\t').collect();
        assert_eq!(columns.len(), 6, "logo clearance table has six columns");
        if columns[5] != "allow" {
            continue;
        }
        let key = columns[0];
        let path = format!("assets/logos/{key}.svg");
        println!("cargo:rerun-if-changed={path}");
        let svg = fs::read_to_string(&path).expect("read cleared upstream logo");
        assert!(svg.starts_with("<svg "), "logo has a plain SVG root");
        assert!(
            !svg.contains("style=") && !svg.contains("<style"),
            "logo uses presentation attributes"
        );
        let symbol = svg
            .replacen("<svg ", &format!("<symbol id=\"img-{key}\" "), 1)
            .replace("</svg>", "</symbol>");
        generated.push_str(&format!("({key:?}, {:?}, {symbol:?}),\n", columns[4]));
    }
    generated.push_str("];\n");
    fs::write(out_dir.join("image_logos.rs"), generated).expect("write embedded logo symbols");
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
