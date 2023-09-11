use crate::parser;
use crate::parser::endian;
use crate::parser::endian::EndianParse;

#[derive(Debug,Clone,PartialEq)]
struct DexProtoId{
    pub shortyIdx:u32,
    pub returnTypeIdx:u32,
    pub parametersOff:u32,
}

impl DexProtoId {
    pub fn read_dex_data(file_path:&str,proto_ids_off:u32,proto_ids_size:u32)->Vec<DexProtoId>{
        let mut v:Vec<DexProtoId>=Vec::new();
        const DexProtoIdSIZE: usize = core::mem::size_of::<DexProtoId>();
        let endian=endian::AnyEndian::new(1);
        let dex_string_bytes=parser::file_stream::file_utils::read_file_range
            (file_path, proto_ids_off as u64, (proto_ids_off+proto_ids_size*(DexProtoIdSIZE as u32)) as u64).unwrap();

        return v;
    }
    
}
