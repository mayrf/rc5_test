use std::fs;
use rc5_test;
use clap::{Arg,App};

// This is an example CLI application that utilises the 
// rc5_test library to encrypt/decrypt an input file 
// specified by --file FILEPATH with a key provided as 
// a string via --key KEY. The output gets saved as 
// FILEPATH_encoded, respectivly FILEPATH_decoded.
//

fn main() {

    let m = App::new("RC5 Cipher")
    .author("Fritz Mayr, f.mayr@hotmail.com")
    .version("0.1.0")
    .about("Encryption and decryption of files with RC5 cipher")
    .arg(Arg::new("file")
        .short('f')
        .long("file")
        .required(true)
        .takes_value(true))
    .arg(Arg::new("key")
        .short('k')
        .long("key")
        .required(true)
        .takes_value(true))
    .arg(Arg::new("word")
        .short('w')
        .long("word")
        .default_value("32")
        .takes_value(true))
        .about("Sets the size of words")
    .arg(Arg::new("rounds")
        .short('r')
        .long("rounds")
        .default_value("12")
        .takes_value(true))
        .about("Sets the number of rounds")
    .arg(Arg::new("encrypt")
        .short('e')
        .long("encrypt"))
    .arg(Arg::new("decrypt")
        .short('d')
        .long("decrypt"))
    .after_help("Longer explanation to appear after the options when \
                 displaying the help information from --help or -h")
    .get_matches();


    let filename = m.value_of("file").unwrap();
    let key = String::from(m.value_of("key").unwrap()).into_bytes();
    let word = m.value_of("word").unwrap().parse::<usize>().unwrap();
    let rounds = m.value_of("rounds").unwrap().parse::<usize>().unwrap();

    if key.len() > 255 {
        panic!("Key too long, has {} bytes,  maximum size is 255 bytes bytes", key.len());
    };
    let config = rc5_test::Config::new(word, rounds, key.len());
    let contents = fs::read(filename)
        .expect("Something went wrong reading the file");

    if m.is_present("encrypt") {
        println!("Encrypting file: {}", filename);
        let res = rc5_test::encode(key, contents, config);
        fs::write(format!("{}_encoded" , filename), res).unwrap();
        println!("Done!");
    } else if m.is_present("decrypt") {
        println!("Decrypting file: {}", filename);
        let res = rc5_test::decode(key, contents, config);
        fs::write(format!("{}_decoded" , filename), res).unwrap();
        println!("Done!");
    } else {
        println!("Please specify mode via --encrypt, -e, --decrypt or -d")
    }
}
