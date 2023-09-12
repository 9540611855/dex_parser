use crate::parser;
use crate::parser::endian;
use crate::parser::endian::EndianParse;

#[derive(Debug,Clone,PartialEq)]
pub struct DexClassDef {
    classIdx: u32,
    accessFlags: u32,
    superclassIdx: u32,
    interfacesOff: u32,
    sourceFileIdx: u32,
    annotationsOff: u32,
    classDataOff: u32,
    staticValuesOff: u32,
}

impl DexClassDef{
    pub fn read_dex_classdefs(file_path:&str,classdef_off:u32,classdef_size:u32)->Vec<DexClassDef>{
        let mut v:Vec<DexClassDef>=Vec::new();
        const DexClassDefSIZE: usize = core::mem::size_of::<DexClassDef>();
        let dex_class_bytes=parser::file_stream::file_utils::read_file_range
            (file_path, classdef_off as u64, (classdef_off+classdef_size*(DexClassDefSIZE as u32)) as u64).unwrap();
        for idx in  0..classdef_size{
            let dex_classdef=Self::parser_dex_classdef
                (dex_class_bytes[(idx as usize*DexClassDefSIZE)..((idx+1) as usize*DexClassDefSIZE)].to_vec());
            v.push(dex_classdef);
        }
        return v;
    }
    pub fn parser_dex_classdef(dex_class_bytes:Vec<u8>)->DexClassDef{
        let endian=endian::AnyEndian::new(1);
        let mut offset:usize=0;
        let classIdx=endian.parse_u32_at(&mut offset, &dex_class_bytes);
        let accessFlags=endian.parse_u32_at(&mut offset, &dex_class_bytes);
        let superclassIdx=endian.parse_u32_at(&mut offset, &dex_class_bytes);
        let interfacesOff=endian.parse_u32_at(&mut offset, &dex_class_bytes);
        let sourceFileIdx=endian.parse_u32_at(&mut offset, &dex_class_bytes);
        let annotationsOff=endian.parse_u32_at(&mut offset, &dex_class_bytes);
        let classDataOff=endian.parse_u32_at(&mut offset, &dex_class_bytes);
        let staticValuesOff=endian.parse_u32_at(&mut offset, &dex_class_bytes);
        return DexClassDef{
            classIdx,
            accessFlags,
            superclassIdx,
            interfacesOff,
            sourceFileIdx,
            annotationsOff,
            classDataOff,
            staticValuesOff,
        }
    }
}


pub struct classData{
     staticFieldsSize:u8,
     instanceFieldsSize:u8,
     directMethodsSize:u8,
     virtualMethodsSize:u8,

}

pub struct DexField{
    fieldIdx:u32,
    accessFlags:u32,
}

pub struct DexMethod {
    methodIdx:u32,
    accessFlags:u32,
    codeOff:u32,
}
pub struct DexCode {
    registers_size: u16,
    ins_size: u16,
    outs_size: u16,
    tries_size: u16,
    debug_info_off: u32,
    insns_size: u32,
    insns: [u16],
}


impl classData{
    fn uleb128_value(data: &[u8], off: usize) -> (u32, usize) {
        let mut size = 1;
        let mut result = data[off] as u32;

        if result > 0x7f {
            let cur = data[off+1];
            result = (result & 0x7f) | ((cur & 0x7f) as u32) << 7;
            size += 1;

            if cur > 0x7f {
                let cur = data[off+2];
                result |= ((cur & 0x7f) as u32) << 14;
                size += 1;

                if cur > 0x7f {
                    let cur = data[off+3];
                    result |= ((cur & 0x7f) as u32) << 21;
                    size += 1;

                    if cur > 0x7f {
                        let cur = data[off+4];
                        result |= (cur as u32) << 28;
                        size += 1;
                    }
                }
            }
        }

        (result, size)
    }

    pub fn read_dex_class_data(file_path:&str,class_defs:Vec<DexClassDef>,file_size:u32){
        for class_def in class_defs{
            let class_data_off=class_def.classDataOff;


        }
    }
    pub fn parser_dex_class_data(){

    }
}
