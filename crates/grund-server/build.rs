use std::{env, fs, io::Write, path::Path};

use flate2::{Compression, write::GzEncoder};

fn main() {
    sedge_gen::build("templates");

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
