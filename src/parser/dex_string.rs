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
            (file_path, string_data as u64, (string_data + 258) as u64).unwrap();
        let len=dex_string_bytes[0];

        let data = &dex_string_bytes[1..(len as u32+1) as usize];


        //string_data[len]!=0?
        if dex_string_bytes[(len as u32+1) as usize]!=0{

            let end =dex_string_bytes[(len as u32+1) as usize..].iter().position(|&b| b == 0);
            if end==None{
                return StringData{
                    len,
                    data: data.to_vec(),
                }
            }
            let data = &dex_string_bytes[1..end.unwrap()+len as usize+1];
            return StringData{
                len,
                data: data.to_vec(),
            }
        }
        return StringData{
            len,
            data: data.to_vec(),
        }
    }
    pub fn print_data(dex_datas:Vec<StringData>){
        for dex_data in dex_datas{
            let string_from_vec = match String::from_utf8(dex_data.data) {
                Ok(s) => s,
                Err(e) => {
                    continue; // skip this iteration if there is an error
                }
            };
            println!("{string_from_vec}");
        }

    }
    pub fn print_data_by_idx(dex_datas:Vec<StringData>,idx:usize)->bool{
            let dex_data=&dex_datas[idx];
            let string_from_vec = match String::from_utf8(dex_data.data.clone()) {
                Ok(s) => s,
                Err(e) => {
                    return false;
                }
            };
            println!("{string_from_vec}");
        return true;
    }
    pub fn get_data_by_idx(dex_datas:Vec<StringData>,idx:usize)->Option<String>{
        let dex_data=&dex_datas[idx];
        let string_from_vec = match String::from_utf8(dex_data.data.clone()) {
            Ok(s) => s,
            Err(e) => {
                return None;
            }
        };
        return Some(string_from_vec);
    }
}