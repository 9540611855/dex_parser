use crate::parser;
use crate::parser::endian;
use crate::parser::endian::{AnyEndian, EndianParse};

#[derive(Debug,Clone,PartialEq)]
pub struct DexProtoId{
    pub shortyIdx:u32,
    pub returnTypeIdx:u32,
    pub parametersOff:u32,
}
#[derive(Debug,Clone,PartialEq)]
pub struct ProtoParameters{
    pub parameters_size:u32,
    pub type_id:Vec<u16>,
}

impl DexProtoId {
    pub fn read_dex_proto(file_path:&str,proto_ids_off:u32,proto_ids_size:u32)->Vec<DexProtoId>{
        let mut v:Vec<DexProtoId>=Vec::new();
        const DexProtoIdSIZE: usize = core::mem::size_of::<DexProtoId>();
        let endian=endian::AnyEndian::new(1);
        let dex_proto_bytes=parser::file_stream::file_utils::read_file_range
            (file_path, proto_ids_off as u64, (proto_ids_off+proto_ids_size*(DexProtoIdSIZE as u32)) as u64).unwrap();
        for idx in  0..proto_ids_size{
            let dex_proto=Self::parser_dex_proto
                (dex_proto_bytes[(idx as usize*DexProtoIdSIZE)..((idx+1) as usize*DexProtoIdSIZE)].to_vec(),endian);
            v.push(dex_proto);
        }
        return v;
    }
    pub fn parser_dex_proto(dex_proto_bytes: Vec<u8>, endian:AnyEndian) ->DexProtoId{
        let mut offset:usize=0;
        let shortyIdx=endian.parse_u32_at(&mut offset, &dex_proto_bytes);
        let returnTypeIdx=endian.parse_u32_at(&mut offset, &dex_proto_bytes);
        let parametersOff=endian.parse_u32_at(&mut offset, &dex_proto_bytes);
        return DexProtoId{
            shortyIdx,
            returnTypeIdx,
            parametersOff,
        }
    }
    
}

impl ProtoParameters{
    pub fn read_dex_proto_parameter(file_path:&str,dex_proto_ids: Vec<DexProtoId>)->Vec<ProtoParameters>{
        //const ProtoParametersSIZE: usize = core::mem::size_of::<ProtoParameters>();
        let mut v:Vec<ProtoParameters>=Vec::new();
        let mut count=0;
        for dex_proto_id in dex_proto_ids{
            let parameter_off=dex_proto_id.parametersOff as u64;
            count+=1;
            if parameter_off==0 {
                let null_proto_parameters = ProtoParameters {
                    parameters_size: 0,
                    type_id: Vec::new(),
                };
                v.push(null_proto_parameters);
                continue;
            }

            let dex_proto_parameters=Self::parser_dex_proto_parameter(file_path,parameter_off);
            v.push(dex_proto_parameters);
        }
        return v;
    }
    pub fn parser_dex_proto_parameter(file_path:&str,parameter_off:u64)->ProtoParameters{
        const U16SIZE: usize = core::mem::size_of::<u16>();
        const U32SIZE: usize = core::mem::size_of::<u32>();
        let endian=endian::AnyEndian::new(1);

        let dex_proto_parameter_bytes=parser::file_stream::file_utils::read_file_range
            (file_path, parameter_off, (parameter_off + U32SIZE as u64) as u64).unwrap();

        let mut offset:usize=0;
        let mut type_id:Vec<u16>=Vec::new();
        let parameters_size=endian.parse_u32_at(&mut 0, &dex_proto_parameter_bytes);

        let type_size=parameters_size*U16SIZE as u32;

        let dex_proto_parameter_bytes=parser::file_stream::file_utils::read_file_range
            (file_path, parameter_off+ U32SIZE as u64,
             (parameter_off +U32SIZE as u64+ type_size as u64) as u64).unwrap();

        for _ in 0..parameters_size{
            let type_idx=endian.parse_u16_at(&mut offset, &dex_proto_parameter_bytes);
            type_id.push(type_idx);
        }
        return ProtoParameters{
            parameters_size,
            type_id,
        }
    }
}
