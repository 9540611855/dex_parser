use crate::parser;
use crate::parser::dex_string::StringData;
use crate::parser::endian;
use crate::parser::endian::EndianParse;

#[derive(Debug,Clone,PartialEq)]
pub struct DexTypeId {
    pub descriptor_idx: u32,
}

impl DexTypeId {
    pub fn read_dex_string(file_path:&str,type_ids_off:u32,type_ids_size:u32)->Vec<DexTypeId>{
        const U32Size: usize = core::mem::size_of::<u32>();
        let endian=endian::AnyEndian::new(1);
        let  mut v: Vec<DexTypeId>=Vec::new();
        let dex_string_bytes=parser::file_stream::file_utils::read_file_range
            (file_path, type_ids_off as u64, (type_ids_off+type_ids_size*(U32Size as u32)) as u64).unwrap();
        let mut offset=0;
        for _ in 0..type_ids_size{
            let string_id= endian.parse_u32_at(&mut offset, &dex_string_bytes);
            let dex_string = DexTypeId {
                descriptor_idx: string_id,
            };
            v.push(dex_string);
        }
        return  v;
    }
    pub fn print_all_type(dex_types:Vec<DexTypeId>,dex_datas:Vec<StringData>){
            for dex_type in dex_types{
                let idx=dex_type.descriptor_idx as usize;
                parser::dex_string::StringData::print_data_by_idx(dex_datas.clone(),idx);
            }
    }
}