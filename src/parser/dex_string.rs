use crate::parser;
use crate::parser::endian;
use crate::parser::endian::EndianParse;
#[derive(Debug,Clone,PartialEq)]
pub struct DexStringId {
    pub string_data_off: u32,
}
#[derive(Debug,Clone,PartialEq)]
pub struct StringData {
    pub len: u8,
    pub data: Vec<u8>,
}

impl DexStringId{
    pub fn read_dex_string(file_path:&str,string_ids_off:u32,string_ids_size:u32)->Vec<DexStringId>{
        const U32Size: usize = core::mem::size_of::<u32>();
        let endian=endian::AnyEndian::new(1);
        let  mut v: Vec<DexStringId>=Vec::new();
        let dex_string_bytes=parser::file_stream::file_utils::read_file_range
            (file_path, string_ids_off as u64, (string_ids_off+string_ids_size*(U32Size as u32)) as u64).unwrap();
        let mut offset=0;
        for idx in 0..string_ids_size{
           let string_id= endian.parse_u32_at(&mut offset, &dex_string_bytes);
            let dex_string = DexStringId {
                string_data_off: string_id,
            };
            v.push(dex_string);
        }
        return  v;
    }
}


impl StringData{
    pub fn read_dex_data(file_path:&str,string_ids:Vec<DexStringId>)->Vec<StringData>{
        let  mut v: Vec<StringData>=Vec::new();
        for string_id in string_ids{
           let string_data= string_id.string_data_off;
            let parser_dex_data=Self::parser_dex_data(file_path,string_data);
            v.push(parser_dex_data);
        }
        return  v;
    }
    pub fn parser_dex_data(file_path:&str,string_data:u32)->StringData{
        //1 bit max =0xff
        let dex_string_bytes=parser::file_stream::file_utils::read_file_range
            (file_path, string_data as u64, (string_data + 256) as u64).unwrap();
        let len=dex_string_bytes[0];
        println!("{len}");
        let data = &dex_string_bytes[1..(len+1) as usize];
        println!("{:?}",data);
        return StringData{
            len,
            data: data.to_vec(),
        }
    }
}