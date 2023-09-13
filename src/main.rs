extern crate core;

use std::env;
use crate::parser::dex_header::header;

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
    let verify_res= parser::dex_header::header::verify_dex(file_path,dex_header.clone().unwrap());

    if !verify_res{
        println!("[!]dex 校验失败");
        return;
    }
    let dex_header=dex_header.clone().unwrap();
    //解析dex_string
    let dex_string=parser::dex_string::DexStringId::read_dex_string
        (file_path,dex_header.string_ids_off,dex_header.string_ids_size);
    let dex_datas=parser::dex_string::StringData::read_dex_data(file_path,dex_string);
    //parser::dex_string::StringData::print_data_by_idx(dex_datas,0x4700);
    let dex_types=parser::dex_type::DexTypeId::read_dex_type
        (file_path,dex_header.type_ids_off,dex_header.type_ids_size);

    //parser::dex_type::DexTypeId::print_all_type(dex_types,dex_datas);
    //parser proto
    let dex_protos=parser::dex_proto::DexProtoId::read_dex_proto
        (file_path,dex_header.proto_ids_off,dex_header.proto_ids_size);

    let dex_proto_paramters=parser::dex_proto::ProtoParameters::
    read_dex_proto_parameter(file_path,dex_protos);
    //println!("{:?}",dex_proto_paramters);
    let dex_fields=parser::dex_field
    ::DexFieldId::read_dex_field(file_path,dex_header.field_ids_off,dex_header.field_ids_size);
    //println!("{:?}",dex_field);

    let dex_methods=parser::dex_method::DexMethodId
    ::read_dex_method(file_path,dex_header.method_ids_off,dex_header.method_ids_size);
    //println!("{:?}",dex_methods);
    let dex_classdefs=parser::dex_classdef
    ::DexClassDef::read_dex_classdefs(file_path,dex_header.class_defs_off,dex_header.class_defs_size);
    println!("{:?}",dex_classdefs);

    let class_datas=parser::dex_classdef::classData::read_dex_class_data
        (file_path,dex_classdefs,dex_header.file_size);
    println!("{:?}",class_datas);

}
