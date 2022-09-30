use std::net::UdpSocket;
use std::str;

#[derive(Debug)]
enum StunMessageClass {
    Request,
    Indication,
    SuccessResponse,
    ErrorResponse,
}

impl StunMessageClass {
    fn str_to_class(str: &str) -> StunMessageClass {
        match str {
            "00" => StunMessageClass::Request,
            "01" => StunMessageClass::Indication,
            "10" => StunMessageClass::SuccessResponse,
            "11" => StunMessageClass::ErrorResponse,
            _ => {
                eprintln!("error");
                std::process::exit(1);
            }
        }
    }

    fn class_to_str<'a>(class: StunMessageClass) -> &'a str {
        match class {
            StunMessageClass::Request => "00",
            StunMessageClass::Indication => "01",
            StunMessageClass::SuccessResponse => "10",
            StunMessageClass::ErrorResponse => "11",
            _ => {
                eprintln!("error");
                std::process::exit(1);
            }
        }
    }
}

#[derive(Debug)]
enum StunMessageMethod {
    Binding,
    Allocate,
    Refresh,
    Send,
    Data,
    CreatePermission,
    ChannelBind,
}

#[derive(Debug)]
struct StunMessageType {
    class: StunMessageClass,
    method: StunMessageMethod,
}

#[derive(Debug)]
struct StunMessageHeader {
    message_type: StunMessageType,
    message_length: String,
    magic_cookie: String,
    transaction_id: String,
}

#[derive(Debug)]
struct StunMessageAttribute {
    attribute_type: String,
    length: String,
    value: String,
}

#[derive(Debug)]
struct StunMessage {
    header: StunMessageHeader,
    attribute: StunMessageAttribute,
}

impl StunMessage {
    fn build(&self) -> String {
        let init = String::from("00");
        let class = match self.header.message_type.class {
            StunMessageClass::Request => "00",
            StunMessageClass::Indication => "01",
            StunMessageClass::SuccessResponse => "10",
            StunMessageClass::ErrorResponse => "11",
            _ => {
                eprintln!("error");
                std::process::exit(1);
            }
        };
        let c0 = &class[0..1];
        let c1 = &class[1..];

        let method = match self.header.message_type.method {
            StunMessageMethod::Binding => "00001",
            StunMessageMethod::Allocate => "00011",
            StunMessageMethod::Refresh => "00100",
            StunMessageMethod::Send => "00110",
            StunMessageMethod::Data => "00111",
            StunMessageMethod::CreatePermission => "01000",
            StunMessageMethod::ChannelBind => "01001",
            _ => {
                eprintln!("error");
                std::process::exit(1);
            }
        };

        let message_type = String::from("000000") + c1 + "000" + c0 + method;

        let header = message_type
            + &*self.header.message_length
            + &*self.header.magic_cookie
            + &*self.header.transaction_id;
        let attribute = self.attribute.attribute_type.clone()
            + &*self.attribute.length
            + &*self.attribute.value;

        return init + &*header + &*attribute;
    }
}

pub fn serve(address: &str) -> Result<(), failure::Error> {
    let server_socket = UdpSocket::bind(address)?;
    loop {
        let mut buffer = [0u8; 1024];
        let (size, src) = server_socket.recv_from(&mut buffer)?;
        println!("Handling from {}", src);

        // byte列を8bitの配列に直す
        let bits: Vec<_> = buffer.iter().map(|x| format!("{:0>8b}", x)).collect();
        let bits_header = &bits[0..20];
        let bits_attribute = &bits[20..];

        let mut message_type = bits_header[0..2].concat();
        // println!("message_type: {}", message_type);
        let c0 = message_type.remove(11);
        let c1 = message_type.remove(7);
        // println!("{}, {}", c0, c1);
        let message_class = format!("{}{}", c0, c1);
        // println!("message_class: {}", message_class);
        let class = StunMessageClass::str_to_class(&*message_class);
        // println!("{:?}", class);

        // println!("message_type: {}", message_type);
        let message_type_byte = format!("{:b}", i64::from_str_radix(&*message_type, 2).unwrap());
        // println!("{:?}", message_type_byte);
        let method = match &*message_type_byte {
            "1" => StunMessageMethod::Binding,
            "11" => StunMessageMethod::Allocate,
            "100" => StunMessageMethod::Refresh,
            "110" => StunMessageMethod::Send,
            "111" => StunMessageMethod::Data,
            "1000" => StunMessageMethod::CreatePermission,
            "1001" => StunMessageMethod::ChannelBind,
            _ => {
                eprintln!("error");
                std::process::exit(1);
            }
        };
        // println!("method: {:?}", method);

        let message_type = StunMessageType { class, method };

        let message_length = bits_header[2..4].concat();
        let magic_cookie = bits_header[4..8].concat();
        let tobe_magic_cookie = format!("{:032b}", 0x2112A442);
        if (magic_cookie == tobe_magic_cookie) {
            println!("magic_cookie ok");
        } else {
            println!("magic_cookie ng");
        }
        let transaction_id = bits_header[8..20].concat();

        let message_header = StunMessageHeader {
            message_type,
            message_length,
            magic_cookie,
            transaction_id,
        };
        println!("message_header: {:?}", message_header);

        let attribute_type = bits_attribute[0..2].concat();
        let attribute_length = bits_attribute[2..4].concat();
        let attribute_value = bits_attribute[4..].concat();
        let message_attribute = StunMessageAttribute {
            attribute_type,
            length: attribute_length,
            value: attribute_value,
        };
        println!("message_attribute: {:?}", message_attribute);

        let response_header = StunMessageHeader {
            message_type: StunMessageType {
                class: StunMessageClass::SuccessResponse,
                method: StunMessageMethod::Binding,
            },
            message_length: "".to_string(),
            magic_cookie: tobe_magic_cookie.to_string(),
            transaction_id: "".to_string(),
        };

        let xor_mapped_address_type = format!("{:016b}", 0x0020);

        let response_attribute = StunMessageAttribute {
            attribute_type: xor_mapped_address_type,
            length: String::from("0000000000010000"),
            value: String::from(""),
        };
        let response_message = StunMessage {
            header: response_header,
            attribute: response_attribute,
        };

        let response_message_str = StunMessage::build(&response_message);

        server_socket.send_to(&buffer, src)?;
    }
}
