extern crate core;

use std::env;

mod parser;

fn main() {
    let args: Vec<String> = env::args().collect();
    let args_len=args.len();
    if args_len<2{
        println!("[!]please input parser dex file path");
        return;
    }
    let file_path=&args[1];

    let dex_header=parser::dex_header::header::read_dex_header(file_path);
    if dex_header==None{
        println!("[!]dex 头解析失败");
        return;
    }
    let verify_res= parser::dex_header::header::verify_dex(file_path,dex_header.unwrap());

    if !verify_res{
        println!("[!]dex 校验失败");
        return;
    }
    

}
