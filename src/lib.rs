use neon::prelude::*;


extern crate rabe;
use crate::rabe::schemes::*;
use rabe::utils::policy::pest::PolicyLanguage;

 

fn setup(mut cx: FunctionContext) -> JsResult<JsArray> {
    let keys_array: Handle<JsArray> = JsArray::new(&mut cx, 2);
    let (pk, msk) = bsw::setup();
    let pk_handle = cx.string(serde_json::to_string(&pk).unwrap());
    let msk_handle = cx.string(serde_json::to_string(&msk).unwrap());
    //let msk_ser = serde_json::to_string(&msk).unwrap();
    keys_array.set(&mut cx, 0, pk_handle)?;
    keys_array.set(&mut cx, 1, msk_handle)?;
    Ok(keys_array)
}

fn encrypt(mut cx: FunctionContext) -> JsResult<JsString> {
    //&pk, &policy, &plaintext
    let pk_handle: Handle<JsString> = cx.argument(0)?;
    let pk_json: String = pk_handle.value(&mut cx);
    let pk: bsw::CpAbePublicKey = serde_json::from_str(&pk_json).unwrap();

    let pol_handle: Handle<JsString> = cx.argument(1)?;
    let policy: String = pol_handle.value(&mut cx);

    let plaintext_buf = cx.argument::<JsBuffer>(2)?;
    let slice = cx.borrow(&plaintext_buf, |data: neon::borrow::Ref<neon::types::BinaryData>| {
        data.as_slice::<u8>()
    });
    let plaintext = slice.to_vec();

    let ct_cp: bsw::CpAbeCiphertext = bsw::encrypt(&pk, &policy, &plaintext, PolicyLanguage::HumanPolicy).unwrap();

    let ct_cp_handle = cx.string(serde_json::to_string(&ct_cp).unwrap());

    Ok(ct_cp_handle)
}

fn encrypt_str(mut cx: FunctionContext) -> JsResult<JsString> {
    //&pk, &policy, &plaintext
    let pk_handle: Handle<JsString> = cx.argument(0)?;
    let pk_json: String = pk_handle.value(&mut cx);
    let pk: bsw::CpAbePublicKey = serde_json::from_str(&pk_json).unwrap();

    let pol_handle: Handle<JsString> = cx.argument(1)?;
    let policy: String = pol_handle.value(&mut cx);

    let pt_handle: Handle<JsString> = cx.argument(2)?;
    let plaintext_str: String = pt_handle.value(&mut cx);
    let plaintext = plaintext_str.into_bytes();

    let ct_cp: bsw::CpAbeCiphertext = bsw::encrypt(&pk, &policy, &plaintext, PolicyLanguage::HumanPolicy).unwrap();

    let ct_cp_handle = cx.string(serde_json::to_string(&ct_cp).unwrap());

    Ok(ct_cp_handle)
}

fn keygen(mut cx: FunctionContext) -> JsResult<JsString> {
    //&pk, &msk, policy array
    let pk_handle: Handle<JsString> = cx.argument(0)?;
    let pk_json: String = pk_handle.value(&mut cx);
    let pk: bsw::CpAbePublicKey = serde_json::from_str(&pk_json).unwrap();

    let msk_handle: Handle<JsString> = cx.argument(1)?;
    let msk_json: String = msk_handle.value(&mut cx);
    let msk: bsw::CpAbeMasterKey = serde_json::from_str(&msk_json).unwrap();

    // policy vector
    let pol_handle: Handle<JsString> = cx.argument(2)?;
    let pol_json: String = pol_handle.value(&mut cx);
    let pol_vec: Vec<String> = serde_json::from_str(&pol_json).unwrap(); 
    
    //let sk: bsw::CpAbeSecretKey = bsw::keygen(&pk, &msk, &vec!["A".to_string(), "B".to_string()]).unwrap();
    let sk: bsw::CpAbeSecretKey = bsw::keygen(&pk, &msk, &pol_vec).unwrap();
    let sk_handle = cx.string(serde_json::to_string(&sk).unwrap());

    Ok(sk_handle)
}


fn decrypt_str(mut cx: FunctionContext) -> JsResult<JsString> {
    //&sk, &cifer
    let sk_handle: Handle<JsString> = cx.argument(0)?;
    let sk_json: String = sk_handle.value(&mut cx);
    let sk: bsw::CpAbeSecretKey = serde_json::from_str(&sk_json).unwrap();

    let ct_cp_handle: Handle<JsString> = cx.argument(1)?;
    let ct_cp_json: String = ct_cp_handle.value(&mut cx);
    let ct_cp: bsw::CpAbeCiphertext = serde_json::from_str(&ct_cp_json).unwrap();

    let plaintext_byte = bsw::decrypt(&sk, &ct_cp).unwrap();
    let plaintext:String = String::from_utf8(plaintext_byte).unwrap();
    //let pt_handle = cx.string(serde_json::to_string(&plaintext).unwrap());

    let pt_handle = cx.string(&plaintext);
    Ok(pt_handle)
}

fn decrypt(mut cx: FunctionContext) -> JsResult<JsBuffer> {
    //&sk, &cifer
    let sk_handle: Handle<JsString> = cx.argument(0)?;
    let sk_json: String = sk_handle.value(&mut cx);
    let sk: bsw::CpAbeSecretKey = serde_json::from_str(&sk_json).unwrap();

    let ct_cp_handle: Handle<JsString> = cx.argument(1)?;
    let ct_cp_json: String = ct_cp_handle.value(&mut cx);
    let ct_cp: bsw::CpAbeCiphertext = serde_json::from_str(&ct_cp_json).unwrap();

    let plaintext_byte = bsw::decrypt(&sk, &ct_cp).unwrap();

    //println!("{:?}",plaintext_byte);
    //let plaintext_buf = &plaintext_byte[..];
    //println!("{:?}",plaintext_buf);

    //let mut buf = cx.buffer(plaintext_byte)?;
    let buffer = JsBuffer::external(&mut cx, plaintext_byte);
    Ok(buffer)
}

/*fn enc(mut cx: FunctionContext) -> JsResult<JsString> {
    let mut owned_string: String = "PPL ".to_owned();

    let s: Handle<JsString> = cx.argument(0)?;
    let str: String = s.value(&mut cx); // JsString::value()
    owned_string.push_str(&str);
    Ok(cx.string(owned_string))    

}*/

fn test_vec(mut cx: FunctionContext) -> JsResult<JsString> {
      // convert a JsArray to a Rust Vec
    let js_arr_handle = cx.argument::<JsArray>(0)?;

    let js_vec: Vec<Handle<JsValue>> = js_arr_handle.to_vec(&mut cx)?;
    let mut phone_list: Vec<String> = Vec::new();
    for (_, item) in js_vec.iter().enumerate() {
        let js_string = item.downcast::<JsString, _>(&mut cx).unwrap();
        println!("{}",js_string.value(&mut cx));
        phone_list.push(js_string.value(&mut cx));
    }

    Ok(cx.string("PP"))

}

/*fn test_vec(mut cx: FunctionContext) -> JsResult<JsBuffer> {
    let str_1: String = String::from_str("PPL");
    let str_by = str_1.into_bytes();

    let mut str_buf = JsBuffer::new(&mut cx, 32);
    buf_copy_from_slice(&str_by, &mut str_buf);

    Ok(str_buf)
}*/

fn make_an_array(mut cx: FunctionContext) -> JsResult<JsArray> {
    // Create some values:
    let n = cx.number(9000);
    let s = cx.string("hello");
    let b = cx.boolean(true);

    // Create a new array:
    let array: Handle<JsArray> = cx.empty_array();

    // Push the values into the array:
    array.set(&mut cx, 0, n)?;
    array.set(&mut cx, 1, s)?;
    array.set(&mut cx, 2, b)?;

    // Return the array:
    Ok(array)
}

fn pass_buffer(mut cx: FunctionContext) -> JsResult<JsString> {
    let buf = cx.argument::<JsBuffer>(0)?;
    let slice = cx.borrow(&buf, |data: neon::borrow::Ref<neon::types::BinaryData>| {
        data.as_slice::<u8>()
    });
    println!("{:02x?}",slice.to_vec());

    Ok(cx.string("PP2"))
}


#[neon::main]
fn main(mut cx: ModuleContext) -> NeonResult<()> {
    cx.export_function("encrypt", encrypt)?;
    cx.export_function("encrypt_str", encrypt_str)?;
    cx.export_function("setup", setup)?;
    cx.export_function("keygen", keygen)?;
    cx.export_function("decrypt", decrypt)?;
    cx.export_function("decrypt_str", decrypt_str)?;
    cx.export_function("test_vec", test_vec)?;
    cx.export_function("make_an_array", make_an_array)?;
    cx.export_function("pass_buffer", pass_buffer)?;
    Ok(())
}
