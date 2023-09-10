
use std::mem;
use crate::parser;
use crate::parser::endian;
use crate::parser::endian::EndianParse;
use simd_adler32::Adler32;


use sha1::{Sha1, Digest};
#[derive(Debug,Clone,PartialEq)]
pub struct header{
    magic: [u8; 8],
    checksum: u32,
    signature: [u8; 20],
    file_size: u32,
    header_size: u32,
    endian_tag: u32,
    link_size: u32,
    link_off: u32,
    map_off: u32,
    string_ids_size: u32,
    string_ids_off: u32,
    type_ids_size: u32,
    type_ids_off: u32,
    proto_ids_size: u32,
    proto_ids_off: u32,
    field_ids_size: u32,
    field_ids_off: u32,
    method_ids_size: u32,
    method_ids_off: u32,
    class_defs_size: u32,
    class_defs_off: u32,
    data_size: u32,
    data_off: u32,
}
impl header{
    pub fn read_dex_header(file_path:&str)->Option<header>{
        //0x70
        let dex_header_size = mem::size_of::<header>();
        let header_bytes=parser::file_stream::file_utils::read_file_range(file_path, 0, dex_header_size as u64);
        let header_bytes=match  header_bytes{
            Ok(_) => {header_bytes.unwrap()},
            Err(_) => {return  None},
        };
       let dex_header=Self::parser_dex_header(header_bytes.as_slice());
        return dex_header;
    }
    pub fn verify_dexsum(dexsum_bytes:&[u8],dexsum:u32)->bool{

        let mut adler = Adler32::new();

        adler.write(dexsum_bytes);
        let hash = adler.finish();
        if hash!=dexsum{
            println!("[!]dexsum出错");
            println!("[@]计算出dexsum:{}", hash);
            println!("[@]文件的dexsum{}",dexsum);
            return false;
        }
        return  true;
    }

    pub fn verify_signature(signature_bytes:&[u8], signature: [u8; 20]) ->bool{
        let mut hasher = Sha1::new();

        hasher.update(signature_bytes);
        let calc_signature = hasher.finalize();

        if calc_signature!=signature.into(){
            println!("[!]signature出错");
            println!("[@]计算出的signature:{:?}",calc_signature);
            println!("【@】文件的signature:{:?}",signature);
            return  false;
        }

        return  true;
    }

    pub fn verify_magic(dex_header:header)->bool{

        //验证magic
        let magic=dex_header.magic;
        if magic[0]!=100 ||magic[1]!=101 || magic[2]!=120{
            return false;
        }
        return true;
    }
    pub fn verify_dex(file_path:&str,dex_header:header)->bool{

        //读取dex的全部bytes
        let header_bytes=parser::file_stream::file_utils::read_file_range
            (file_path, 0, dex_header.file_size as u64).unwrap();

        if !Self::verify_magic(dex_header.clone()){
            return false;
        }

        //验证dexsum 去除magic和dexsum 12个字节
        let dex_sum_bytes:&[u8]=&header_bytes[12..];
        let dex_sum_flag=Self::verify_dexsum(dex_sum_bytes,dex_header.checksum);
        if !dex_sum_flag{
            return false;
        }
        //验证signature 去除magic和dexsum signature 32个字节
        let dex_signature_bytes:&[u8]=&header_bytes[32..];

        let dex_signature_flag=Self::verify_signature(dex_signature_bytes,dex_header.signature);
        if !dex_signature_flag{
            return false;
        }
        return true;
    }
    pub fn parser_dex_header(header_bytes:&[u8])->Option<header>{
        //todo 默认小端 是否有增加判断大段的必要？
        let endian=endian::AnyEndian::new(1);
        let mut offset:usize=0;
        let  magic: [u8; 8]=header_bytes[0..8].try_into().unwrap();
        offset+=8;
        let checksum: u32=endian.parse_u32_at(&mut offset, header_bytes);
        let signature: [u8; 20]=header_bytes[offset..offset+20].try_into().unwrap();
        offset+=20;
        let file_size: u32=endian.parse_u32_at(&mut offset, header_bytes);
        let header_size: u32=endian.parse_u32_at(&mut offset, header_bytes);
        let endian_tag: u32=endian.parse_u32_at(&mut offset, header_bytes);
        let link_size: u32=endian.parse_u32_at(&mut offset, header_bytes);
        let link_off: u32=endian.parse_u32_at(&mut offset, header_bytes);
        let map_off: u32=endian.parse_u32_at(&mut offset, header_bytes);
        let string_ids_size: u32=endian.parse_u32_at(&mut offset, header_bytes);
        let string_ids_off: u32=endian.parse_u32_at(&mut offset, header_bytes);
        let type_ids_size: u32=endian.parse_u32_at(&mut offset, header_bytes);
        let type_ids_off: u32=endian.parse_u32_at(&mut offset, header_bytes);
        let proto_ids_size: u32=endian.parse_u32_at(&mut offset, header_bytes);
        let proto_ids_off: u32=endian.parse_u32_at(&mut offset, header_bytes);
        let field_ids_size: u32=endian.parse_u32_at(&mut offset, header_bytes);
        let field_ids_off: u32=endian.parse_u32_at(&mut offset, header_bytes);
        let method_ids_size: u32=endian.parse_u32_at(&mut offset, header_bytes);
        let method_ids_off: u32=endian.parse_u32_at(&mut offset, header_bytes);
        let class_defs_size: u32=endian.parse_u32_at(&mut offset, header_bytes);
        let class_defs_off: u32=endian.parse_u32_at(&mut offset, header_bytes);
        let data_size: u32=endian.parse_u32_at(&mut offset, header_bytes);
        let data_off: u32=endian.parse_u32_at(&mut offset, header_bytes);

        let dex_header=header{
            magic,
            checksum,
            signature,
            file_size,
            header_size,
            endian_tag,
            link_size,
            link_off,
            map_off,
            string_ids_size,
            string_ids_off,
            type_ids_size,
            type_ids_off,
            proto_ids_size,
            proto_ids_off,
            field_ids_size,
            field_ids_off,
            method_ids_size,
            method_ids_off,
            class_defs_size,
            class_defs_off,
            data_size,
            data_off
        };
        println!("{:?}",dex_header);
        return Some(dex_header);
    }

}