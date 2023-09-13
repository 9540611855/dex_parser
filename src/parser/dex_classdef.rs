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

#[derive(Debug,Clone,PartialEq)]
pub struct classData{
     staticFieldsSize:u32,
     instanceFieldsSize:u32,
     directMethodsSize:u32,
     virtualMethodsSize:u32,
     staticField:Vec<DexField>,
     instanceField:Vec<DexField>,
     directMethods:Vec<DexMethod>,
     virtualMethods:Vec<DexMethod>,
}
#[derive(Debug,Clone,PartialEq)]
pub struct DexField{
    fieldIdx:u32,
    accessFlags:u32,
}
#[derive(Debug,Clone,PartialEq)]
pub struct DexMethod {
    methodIdx:u32,
    accessFlags:u32,
    codeOff:u32,
}
#[derive(Debug,Clone,PartialEq)]
pub struct DexCode {
    registers_size: u16,
    ins_size: u16,
    outs_size: u16,
    tries_size: u16,
    debug_info_off: u32,
    insns_size: u32,
    insns: Vec<u8>,
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

    pub fn read_dex_class_data(file_path:&str,class_defs:Vec<DexClassDef>,file_size:u32)->Vec<classData>{
        let mut v:Vec<classData>=Vec::new();
        //read all dex bytes
        let dex_bytes=parser::file_stream::file_utils::read_file_range
            (file_path,0,file_size as u64).unwrap();
        for class_def in class_defs{
            let class_data_off=class_def.classDataOff;
            let (class_data,_)=Self::parser_dex_class_data
                (dex_bytes.clone(), class_data_off as usize);
            v.push(class_data);
        }
        return v;
    }
    pub fn parser_dex_class_data(class_data:Vec<u8>,off:usize)->(classData,usize){
        let mut offset=off;
        let (staticFieldsSize,off_size)=Self::uleb128_value(&class_data,offset);
        offset+=off_size;
        let (instanceFieldsSize,off_size)=Self::uleb128_value(&class_data,offset);
        offset+=off_size;
        let (directMethodsSize,off_size)=Self::uleb128_value(&class_data,offset);
        offset+=off_size;
        let (virtualMethodsSize,off_size)=Self::uleb128_value(&class_data,offset);
        offset+=off_size;
        let (staticField,offset)=Self::parser_dex_class_dex_field
            (class_data.clone(),offset,staticFieldsSize);
        let (instanceField,offset)=Self::parser_dex_class_dex_field
            (class_data.clone(),offset,instanceFieldsSize);
        let (directMethods,offset)=Self::parser_dex_class_dex_method
            (class_data.clone(),offset,directMethodsSize);
        let (virtualMethods,offset)=Self::parser_dex_class_dex_method
            (class_data.clone(),offset,virtualMethodsSize);
        let class_data=classData{
            staticFieldsSize,
            instanceFieldsSize,
            directMethodsSize,
            virtualMethodsSize,
            staticField,
            instanceField,
            directMethods,
            virtualMethods,
        };
        return (class_data,offset);

    }
    pub fn parser_dex_class_dex_field(class_data:Vec<u8>,off:usize,fields_size:u32)->(Vec<DexField>,usize){
        let mut offset=off;
        let mut v:Vec<DexField>=Vec::new();
        for _ in 0..fields_size{
            let (fieldIdx,off_size)=Self::uleb128_value(&class_data,offset);
            offset+=off_size;
            let (accessFlags,off_size)=Self::uleb128_value(&class_data,offset);
            offset+=off_size;
            let dex_field=DexField{fieldIdx, accessFlags};
            v.push(dex_field);
        }

        return (v,offset);
    }

    pub fn parser_dex_class_dex_method(class_data:Vec<u8>,off:usize,methods_size:u32)->(Vec<DexMethod>,usize){

        let mut offset=off;
        let mut v:Vec<DexMethod>=Vec::new();
        for _ in 0..methods_size{
            let (methodIdx,off_size)=Self::uleb128_value(&class_data,offset);
            offset+=off_size;
            let (accessFlags,off_size)=Self::uleb128_value(&class_data,offset);
            offset+=off_size;
            let (codeOff,off_size)=Self::uleb128_value(&class_data,offset);
            offset+=off_size;
            let dex_method=DexMethod{methodIdx, accessFlags,codeOff};
            v.push(dex_method);
        }

        return (v,offset);
    }
}
