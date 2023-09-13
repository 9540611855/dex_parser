use crate::parser;
use crate::parser::dex_field::DexFieldId;
use crate::parser::dex_method::DexMethodId;
use crate::parser::dex_proto::{DexProtoId, ProtoParameters};
use crate::parser::dex_string::{DexStringId, StringData};
use crate::parser::dex_type::DexTypeId;
use crate::parser::endian;
use crate::parser::endian::EndianParse;

#[derive(Debug,Clone,PartialEq,Copy)]
pub struct DexClassDef {
    pub classIdx: u32,
    pub accessFlags: u32,
    pub superclassIdx: u32,
    pub interfacesOff: u32,
    pub sourceFileIdx: u32,
    pub annotationsOff: u32,
    pub classDataOff: u32,
    pub staticValuesOff: u32,
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

    pub fn print_dex_class_dex(file_path:&str,
                               file_size:u32,
                               dex_class_def:DexClassDef,
                               dex_string:Vec<DexStringId>,
                               dex_datas:Vec<StringData>,
                               dex_types:Vec<DexTypeId>,
                               dex_protos:Vec<DexProtoId>,
                               dex_proto_paramters:Vec<ProtoParameters>,
                               dex_fields:Vec<DexFieldId>,
                               dex_methods:Vec<DexMethodId>,
                               //class_datas:Vec<classData>
                               ){
        let class_idx=dex_class_def.classIdx;
        let access_flag=dex_class_def.accessFlags;
        let super_class_idx=dex_class_def.superclassIdx;
        let interfaces_off=dex_class_def.interfacesOff;
        let source_file_idx=dex_class_def.sourceFileIdx;
        let annotation_off=dex_class_def.annotationsOff;
        let class_data_off=dex_class_def.classDataOff;
        let static_values_off=dex_class_def.staticValuesOff;

        let class_type_str=Self::class_type_to_string(class_idx,dex_types.clone(),dex_datas.clone());
        let super_class_str=Self::class_type_to_string(super_class_idx,dex_types.clone(),dex_datas.clone());
        let source_file_str=Self::id_to_string(source_file_idx,dex_datas.clone());

        let class_data=classData::read_dex_one_class_data(file_path,dex_class_def,file_size);

        let static_field_size=class_data.staticFieldsSize;
        let instance_field_size=class_data.instanceFieldsSize;
        let direct_methods_size=class_data.directMethodsSize;
        let virtual_methods_size=class_data.virtualMethodsSize;


        let  static_fields=Self::DexField_to_DexFieldId(class_data.staticField,dex_fields.clone());
        let static_field_strs=Self::parser_field(static_fields.clone(),dex_types.clone(),dex_datas.clone());

        let  instance_fields=Self::DexField_to_DexFieldId(class_data.instanceField,dex_fields.clone());
        let instance_field_strs=Self::parser_field(instance_fields.clone(),dex_types.clone(),dex_datas.clone());

        let direct_methods=Self::DexMethod_to_DexMethodId(class_data.directMethods.clone(),dex_methods.clone());
        let direct_codes=Self::parser_code(file_path,class_data.directMethods.clone(),file_size);
        let direct_methods_strs=Self::parser_method(file_path,direct_methods,
                                            dex_types.clone(),dex_protos.clone(),dex_datas.clone());

        let virtual_methods=Self::DexMethod_to_DexMethodId(class_data.virtualMethods.clone(),dex_methods.clone());
        let virtual_codes=Self::parser_code(file_path,class_data.virtualMethods.clone(),file_size);
        let virtual_methods_strs=Self::parser_method(file_path,virtual_methods,
                                                     dex_types.clone(),dex_protos.clone(),dex_datas.clone());





        println!("********类的基本信息**********");
        println!("类名称:{}",class_type_str);
        println!("父类类型:{}",super_class_str);
        println!("源码文件:{}",source_file_str);
        println!("static 字段个数:{}",static_field_size);
        println!("instance 字段个数:{}",instance_field_size);
        println!("direct 方法个数:{}",direct_methods_size);
        println!("virtual 方法个数:{}",virtual_methods_size);


        println!("********类的字段信息**********");
        if static_field_size>0 {
            println!("static 字段:");
            for field_str in static_field_strs{
                println!("{}",field_str);
            }

        }
        if instance_field_size>0 {
            println!("instance字段:");
            for field_str in instance_field_strs{
                println!("{}",field_str);
            }

        }

        if direct_methods_size>0{
            println!("direct方法:");
            for idx in 0..direct_methods_size{
                let method_str=&direct_methods_strs[idx as usize];
                let dex_code=&direct_codes[idx as usize];
                println!("{:?}",method_str);
                println!("使用的寄存器个数 {}:",dex_code.registers_size);
                println!("参数个数 {}:",dex_code.ins_size);
                println!("调用其他方法时其它方法使用的寄存器个数 {}:",dex_code.outs_size);
                println!("Try/Catch个数 {}:",dex_code.tries_size);
                println!("指向调试信息的偏移 {}:",dex_code.debug_info_off);
                println!("指令集个数 {}:",dex_code.insns_size);
                println!("指令集 {:?}:",dex_code.insns);
            }
        }
        if virtual_methods_size>0{
            println!("direct方法:");
            for idx in 0..virtual_methods_size{
                let method_str=&virtual_methods_strs[idx as usize];
                let dex_code=&virtual_codes[idx as usize];
                println!("{:?}",method_str);
                println!("使用的寄存器个数 {}:",dex_code.registers_size);
                println!("参数个数 {}:",dex_code.ins_size);
                println!("调用其他方法时其它方法使用的寄存器个数 {}:",dex_code.outs_size);
                println!("Try/Catch个数 {}:",dex_code.tries_size);
                println!("指向调试信息的偏移 {}:",dex_code.debug_info_off);
                println!("指令集个数 {}:",dex_code.insns_size);
                println!("指令集 {:?}:",dex_code.insns);
            }
        }


    }

    pub fn DexMethod_to_DexMethodId(dex_methods:Vec<DexMethod>,dex_method_ids:Vec<DexMethodId>)->Vec<DexMethodId>{
        let mut v:Vec<DexMethodId>=Vec::new();
        for dex_method in dex_methods{
            let idx=dex_method.methodIdx;

            let method= &dex_method_ids[idx as usize];
            v.push(*method);
        }
        return v;
    }
    pub fn  parser_code(file_path:&str,dex_methods:Vec<DexMethod>,file_size:u32)->Vec<DexCode>{
        let mut v:Vec<DexCode>=Vec::new();
        for dex_method in dex_methods{
           let code= DexCode::parser_data_code(file_path,dex_method,file_size);
            v.push(code);
        }
        return v;
    }
    pub fn DexField_to_DexFieldId(dex_fields:Vec<DexField>,dex_field_ids:Vec<DexFieldId>)->Vec<DexFieldId>{
        let mut v:Vec<DexFieldId>=Vec::new();
        for dex_field in dex_fields{
            let field_idx=dex_field.fieldIdx;
            let dex_field=&dex_field_ids[field_idx as usize];
            v.push(*dex_field);
        }
        return v;
    }

    pub fn parser_method(file_path:&str,dex_method_ids:Vec<DexMethodId>,
                         dex_types:Vec<DexTypeId>,dex_protos:Vec<DexProtoId>
                         ,dex_datas:Vec<StringData>)->Vec<String>{
        let mut v:Vec<String>=Vec::new();
        for dex_method in dex_method_ids{
            let class_idx=dex_method.classIdx;
            let proto_idx=dex_method.protoIdx;
            let name_idx=dex_method.nameIdx;
            let class_str=Self::class_type_to_string(class_idx as u32, dex_types.clone(), dex_datas.clone());
            let type_str=Self::protos_to_string(file_path,dex_types.clone(),proto_idx as u32, dex_protos.clone(), dex_datas.clone());
            let name_str=Self::id_to_string(name_idx,dex_datas.clone());
            let s = format!("{} {} {}", class_str, type_str, name_str);
            v.push(s);
        }
        return v;
    }
    pub fn protos_to_string(file_path:&str,dex_types:Vec<DexTypeId>,proto_idx:u32,dex_protos:Vec<DexProtoId>,dex_datas:Vec<StringData>)->String{
        let dex_proto=&dex_protos[proto_idx as usize];
        let shorty_idx=dex_proto.shortyIdx;
        let return_type_idx=dex_proto.returnTypeIdx;
        let parameters_off=dex_proto.parametersOff;
        let shorty_str=Self::id_to_string(shorty_idx,dex_datas.clone());
        let return_str=Self::id_to_string(return_type_idx,dex_datas.clone());
        let mut paramters_str="".to_string();
        if parameters_off!=0{
            paramters_str=Self::parameters_to_string(file_path,parameters_off,dex_types,dex_datas);
        }


        let s = format!("{} {}.{}", shorty_str, paramters_str, return_str);
        return s;
    }

    pub fn parameters_to_string(file_path:&str,parameters_off:u32,dex_types:Vec<DexTypeId>,dex_datas:Vec<StringData>)->String{
        let mut s:String = "".to_string();
        let proto_param=ProtoParameters::parser_dex_proto_parameter(file_path,parameters_off as u64);
        let type_ids=proto_param.type_id.clone();
        for type_id  in type_ids{
            let dex_type=&dex_types[type_id as usize];
            let strs=Self::class_type_to_string(type_id as u32,dex_types.clone(),dex_datas.clone());
            s=s+","+ &*strs;
        }
        return s;
    }
    pub fn parser_field(fields:Vec<DexFieldId>,dex_types:Vec<DexTypeId>,dex_datas:Vec<StringData>)->Vec<String>{
        let mut v:Vec<String>=Vec::new();
        for field in fields{
            let class_idx=field.classIdx;
            let type_idx=field.typeIdx;
            let name_idx=field.nameIdx;
            let class_str=Self::class_type_to_string(class_idx as u32, dex_types.clone(), dex_datas.clone());
            let type_str=Self::class_type_to_string(type_idx as u32, dex_types.clone(), dex_datas.clone());
            let name_str=Self::id_to_string(name_idx,dex_datas.clone());
            let s = format!("{} {}.{}", type_str, class_str, name_str);
            v.push(s);

        }
        return  v;
    }

    pub fn class_type_to_string(idx:u32,dex_types:Vec<DexTypeId>,dex_datas:Vec<StringData>)->String{
        let class_type=&dex_types[idx as usize];
        let class_type_str=&dex_datas[class_type.descriptor_idx as usize];
        let string = String::from_utf8(class_type_str.data.clone()).expect("转换失败");
        return string;
    }
    pub fn id_to_string(idx:u32,dex_datas:Vec<StringData>)->String{
        let class_type_str=&dex_datas[idx as usize];
        let string = String::from_utf8(class_type_str.data.clone()).expect("转换失败");
        return string;
    }
}

#[derive(Debug,Clone,PartialEq)]
pub struct classData{
     pub staticFieldsSize:u32,
     pub instanceFieldsSize:u32,
     pub directMethodsSize:u32,
     pub virtualMethodsSize:u32,
     pub staticField:Vec<DexField>,
     pub instanceField:Vec<DexField>,
     pub directMethods:Vec<DexMethod>,
     pub virtualMethods:Vec<DexMethod>,
}
#[derive(Debug,Clone,PartialEq)]
pub struct DexField{
    pub fieldIdx:u32,
    pub accessFlags:u32,
}
#[derive(Debug,Clone,PartialEq)]
pub struct DexMethod {
    pub methodIdx:u32,
    pub accessFlags:u32,
    pub codeOff:u32,
}
#[derive(Debug,Clone,PartialEq)]
pub struct DexCode {
    pub registers_size: u16,
    pub ins_size: u16,
    pub  outs_size: u16,
    pub tries_size: u16,
    pub debug_info_off: u32,
    pub insns_size: u32,
    pub insns: Vec<u16>,
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

    pub fn read_dex_one_class_data(file_path:&str,class_def:DexClassDef,file_size:u32)->classData{
        let dex_bytes=parser::file_stream::file_utils::read_file_range
            (file_path,0,file_size as u64).unwrap();
        let class_data_off=class_def.classDataOff;
        let (class_data,_)=Self::parser_dex_class_data
            (dex_bytes.clone(), class_data_off as usize);
        return  class_data;
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

impl DexCode {
    pub fn parser_data_code(file_path:&str,method_data:DexMethod,file_size:u32)->DexCode{
        let endian=endian::AnyEndian::new(1);
        //read all dex bytes
        let dex_bytes=parser::file_stream::file_utils::read_file_range
            (file_path,0,file_size as u64).unwrap();

        let code_off=method_data.codeOff;
        let mut offset=code_off as usize;
        let registers_size= endian.parse_u16_at(&mut offset, &dex_bytes);
        let ins_size= endian.parse_u16_at(&mut offset, &dex_bytes);
        let outs_size= endian.parse_u16_at(&mut offset, &dex_bytes);
        let tries_size= endian.parse_u16_at(&mut offset, &dex_bytes);
        let debug_info_off= endian.parse_u32_at(&mut offset, &dex_bytes);
        let insns_size= endian.parse_u32_at(&mut offset, &dex_bytes);
        let mut insns:Vec<u16>=Vec::new();
        for _ in 0..insns_size{
            let ins=endian.parse_u16_at(&mut offset,&dex_bytes);
            insns.push(ins);
        }
        return DexCode{
            registers_size,
            ins_size,
            outs_size,
            tries_size,
            debug_info_off,
            insns_size,
            insns,
        }

    }
}