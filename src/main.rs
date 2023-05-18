use std::fs::File;
use regex::Regex;
use std::collections::HashMap;
use entropy::Entropy;

static HIGH_ENTROPY: f32 = 7.0;

fn main() {
    let mut high_risk: HashMap<String, f32> = HashMap::new();

    // Scanning entropy for comadmin.dat
    println!("Scanning for comadmin.dat");
    let fp = "C:\\Windows\\System32\\Com\\comadmin.dat";
    if let Ok(comadmin_file) = File::open(fp) {
        let entropy = Entropy::new(&comadmin_file);
        let result = entropy.shannon_entropy();
        println!("domadmin.dat entropy: {}", result);
        if result > HIGH_ENTROPY {
            high_risk.insert(fp.to_string(), result);
        }
    } else {
        println!("File not found: {}", fp);
    }

    // Scanning entropy for windows/registraion queue files
    println!("Scanning for queue files under C:/Windows/Registration");
    let base_path = "C:\\Windows\\Registration";
    let re = Regex::new(r"(\{[0-9A-F]{8}\-([0-9A-F]{4}\-){3}[0-9A-F]{12}\}\.){2}crmlog").unwrap();
    if let Ok(entries) = std::fs::read_dir(base_path) {
        for entry in entries {
            if let Ok(e) = entry {
                let filepath = e.path();
                let filename = filepath.to_string_lossy().into_owned();
                if re.is_match(&filename) {
                    if let Ok(file) = File::open(&filename) {
                        let entropy = Entropy::new(&file);
                        let result = entropy.shannon_entropy();
                        println!("{} entropy: {}", &filename, result);
                        if result > HIGH_ENTROPY {
                            high_risk.insert(filename, result);
                        }
                    } else {
                        println!("File not found: {}", &filename);
                    }
                }
            }
        }
    }

    if high_risk.len() > 0 {
        println!("\n\n=============HIGH RISK FILES DETECTED==============");
        for (k, v) in high_risk {
            println!("{}: {}", k, v);
        }
        println!("====================================================");
    } else {
        println!("\n\nNo high risk files detected");
    }

    println!("\nScan complete");
}
