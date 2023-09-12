use crate::parser;
use crate::parser::endian;
use crate::parser::endian::EndianParse;

#[derive(Debug,Clone,PartialEq)]
pub struct DexMethodId{
    pub classIdx:u16,
    pub protoIdx:u16,
    pub nameIdx:u32,
}

impl DexMethodId{
    pub fn read_dex_method(file_path:&str,method_ids_off:u32,method_ids_size:u32)->Vec<DexMethodId>{
        let mut v:Vec<DexMethodId>=Vec::new();
        const DexMethodIdSIZE: usize = core::mem::size_of::<DexMethodId>();
        let dex_method_bytes=parser::file_stream::file_utils::read_file_range
            (file_path, method_ids_off as u64, (method_ids_off+method_ids_size*(DexMethodIdSIZE as u32)) as u64).unwrap();
        for idx in  0..method_ids_size{
            let dex_method=Self::parser_dex_method
                (dex_method_bytes[(idx as usize* DexMethodIdSIZE)..((idx+1) as usize*DexMethodIdSIZE)].to_vec());
            v.push(dex_method);
        }
        return v;
    }
    pub fn parser_dex_method(dex_method_bytes:Vec<u8>)->DexMethodId {
        let endian=endian::AnyEndian::new(1);
        let mut offset:usize=0;
        let classIdx=endian.parse_u16_at(&mut offset, &dex_method_bytes);
        let protoIdx=endian.parse_u16_at(&mut offset, &dex_method_bytes);
        let nameIdx=endian.parse_u32_at(&mut offset, &dex_method_bytes);
        return DexMethodId{
            classIdx,
            protoIdx,
            nameIdx,
        }
    }

}