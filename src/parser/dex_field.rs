use crate::parser;
use crate::parser::endian;
use crate::parser::endian::EndianParse;

#[derive(Debug,Clone,PartialEq)]
pub struct DexFieldId{
    pub classIdx:u16,
    pub typeIdx:u16,
    pub nameIdx:u32,
}

impl DexFieldId{
    pub fn read_dex_field(file_path:&str,field_ids_off:u32,field_ids_size:u32)->Vec<DexFieldId>{
        let mut v:Vec<DexFieldId>=Vec::new();
        const DexFieldIdSIZE: usize = core::mem::size_of::<DexFieldId>();
        let dex_field_bytes=parser::file_stream::file_utils::read_file_range
            (file_path, field_ids_off as u64, (field_ids_off+field_ids_size*(DexFieldIdSIZE as u32)) as u64).unwrap();
        for idx in  0..field_ids_size{
            let dex_field=Self::parser_dex_field
                (dex_field_bytes[(idx as usize* DexFieldIdSIZE)..((idx+1) as usize*DexFieldIdSIZE)].to_vec());
            v.push(dex_field);
        }
        return v;
    }
    pub fn parser_dex_field(dex_field_bytes:Vec<u8>)->DexFieldId {
        let endian=endian::AnyEndian::new(1);
        let mut offset:usize=0;
        let classIdx=endian.parse_u16_at(&mut offset, &dex_field_bytes);
        let typeIdx=endian.parse_u16_at(&mut offset, &dex_field_bytes);
        let nameIdx=endian.parse_u32_at(&mut offset, &dex_field_bytes);
        return DexFieldId{
            classIdx,
            typeIdx,
            nameIdx,
        }
    }

}