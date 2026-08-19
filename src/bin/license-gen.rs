use clap::Parser;
use dahua_dhip_adduser::license;

#[derive(Parser)]
#[command(
    name = "license-gen",
    about = "Genera la licenza criptata da scrivere nel file licence.lic"
)]
struct Args {
    /// Machine ID mostrato dalla dialog della GUI (se omesso, calcola quello della macchina corrente)
    machine_id: Option<String>,
    /// Scrivi direttamente il file licence.lic accanto a questo eseguibile
    #[arg(long)]
    write_file: bool,
    /// Percorso alternativo del file da scrivere (al posto di licence.lic)
    #[arg(long)]
    output: Option<String>,
}

fn main() {
    let args = Args::parse();
    let mid = match args.machine_id {
        Some(m) => m.trim().to_string(),
        None => license::machine_id(),
    };

    let payload = license::make_payload(&mid);
    let lic = license::encrypt_license(&payload);

    if args.write_file {
        let path = match args.output {
            Some(p) => std::path::PathBuf::from(p),
            None => license::license_file_path(),
        };
        match std::fs::write(&path, &lic) {
            Ok(()) => println!("[OK] File di licenza scritto: {}", path.display()),
            Err(e) => {
                eprintln!("[ERRORE] Scrittura fallita: {}", e);
                std::process::exit(1);
            }
        }
        println!("Machine ID: {}", mid);
    } else {
        println!("Machine ID: {}", mid);
        println!("Licenza (copiala nella dialog della GUI oppure scrivila nel file licence.lic):");
        println!("{}", lic);
    }
}
