use std::convert::TryInto;
use std::net::{SocketAddr, UdpSocket};
use std::str;

fn vec_to_array<T, const N: usize>(v: Vec<T>) -> [T; N] {
    v.try_into()
        .unwrap_or_else(|v: Vec<T>| panic!("Expected a Vec of length {} but it was {}", N, v.len()))
}

const MAGIC_COOKIE: u32 = 0x2112A442;

fn create_xor_mapped_address_and_port(address_port: SocketAddr) -> [u8; 8] {
    let fix0: u8 = 0x0;
    let family_ipv4: u8 = 0x01;

    let address_port_str = address_port.to_string();
    let address_port_vec: Vec<&str> = address_port_str.split(':').collect();
    let address = address_port_vec[0];
    let port_int: u16 = address_port_vec[1].parse().unwrap();

    let magic_bytes: [u8; 4] = MAGIC_COOKIE.to_be_bytes();
    let magic_bytes_16bits: [u8; 2] = magic_bytes[0..2].try_into().unwrap();
    let magic_16bits = u16::from_be_bytes(magic_bytes_16bits);

    let xor_port_u16: u16 = port_int ^ magic_16bits;
    let xor_port = xor_port_u16.to_be_bytes();

    let address_vec: Vec<&str> = address.split('.').collect();
    let address_vec_int: Vec<u8> = address_vec
        .iter()
        .map(|address| address.parse().unwrap())
        .collect();
    let address_array: [u8; 4] = vec_to_array(address_vec_int);
    let address_int: u32 = u32::from_be_bytes(address_array);
    let xor_address_u32 = address_int ^ MAGIC_COOKIE;
    let xor_address = xor_address_u32.to_be_bytes();

    return [
        fix0,
        family_ipv4,
        xor_port[0],
        xor_port[1],
        xor_address[0],
        xor_address[1],
        xor_address[2],
        xor_address[3],
    ];
}

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
    message_length: [u8; 2],
    magic_cookie: [u8; 4],
    transaction_id: [u8; 12],
}

#[derive(Debug)]
struct StunMessageAttribute {
    attribute_type: [u8; 2],
    length: [u8; 2],
    value: Vec<u8>,
}

#[derive(Debug)]
struct StunMessage {
    header: StunMessageHeader,
    attribute: StunMessageAttribute,
}

impl StunMessage {
    fn build(&self) -> Vec<u8> {
        let class = match self.header.message_type.class {
            StunMessageClass::Request => "00",
            StunMessageClass::Indication => "01",
            StunMessageClass::SuccessResponse => "10",
            StunMessageClass::ErrorResponse => "11",
        };
        let c1 = &class[0..1];
        let c0 = &class[1..];

        let method = match self.header.message_type.method {
            StunMessageMethod::Binding => "0001",
            StunMessageMethod::Allocate => "0011",
            StunMessageMethod::Refresh => "0100",
            StunMessageMethod::Send => "0110",
            StunMessageMethod::Data => "0111",
            StunMessageMethod::CreatePermission => "1000",
            StunMessageMethod::ChannelBind => "1001",
        };

        let message_type_str = String::from("0000000") + c1 + "000" + c0 + method;
        let message_type_u16 = u16::from_str_radix(&*message_type_str, 2).unwrap();
        let message_type = message_type_u16.to_be_bytes();

        let h = &self.header;
        let mut header: Vec<u8> = message_type
            .iter()
            .chain(&h.message_length)
            .chain(&h.magic_cookie)
            .chain(&h.transaction_id)
            .map(|&x| x)
            .collect();

        let a = &self.attribute;
        let mut attribute: Vec<u8> = a
            .attribute_type
            .iter()
            .chain(&a.length)
            .chain(&a.value)
            .map(|&x| x)
            .collect();

        header.append(&mut attribute);
        let message = header;
        return message;
    }
}

pub fn serve(address: &str) -> Result<(), failure::Error> {
    let server_socket = UdpSocket::bind(address)?;
    loop {
        let mut buffer = [0u8; 1024];

        let (_size, src) = server_socket.recv_from(&mut buffer)?;

        let header = &buffer[0..20];
        let attribute = &buffer[20..];

        let message_type_slice: Vec<_> =
            header[0..2].iter().map(|x| format!("{:0>8b}", x)).collect();
        let mut message_type = message_type_slice.concat();

        let c0 = message_type.remove(11);
        let c1 = message_type.remove(7);
        let message_class = format!("{}{}", c0, c1);
        let class = StunMessageClass::str_to_class(&*message_class);

        let message_type_int = i64::from_str_radix(&*message_type, 2).unwrap();
        let method = match message_type_int {
            1 => StunMessageMethod::Binding,
            3 => StunMessageMethod::Allocate,
            4 => StunMessageMethod::Refresh,
            6 => StunMessageMethod::Send,
            7 => StunMessageMethod::Data,
            8 => StunMessageMethod::CreatePermission,
            9 => StunMessageMethod::ChannelBind,
            _ => {
                eprintln!("error");
                std::process::exit(1);
            }
        };
        let message_type = StunMessageType { class, method };

        let message_length_2_bytes: [u8; 2] = header[2..4].try_into().expect("failed to convert");
        let magic_cookie_4_bytes: [u8; 4] = header[4..8].try_into().expect("failed to convert");
        let magic_cookie = format!("0x{:X}", u32::from_be_bytes(magic_cookie_4_bytes));
        if magic_cookie != "0x2112A442" {
            eprintln!("magic_cookie NG");
            std::process::exit(1);
        }
        let transaction_id_12_bytes: [u8; 12] =
            header[8..20].try_into().expect("failed to convert");

        let message_header = StunMessageHeader {
            message_type,
            message_length: message_length_2_bytes,
            magic_cookie: magic_cookie_4_bytes,
            transaction_id: transaction_id_12_bytes,
        };

        let attribute_type: [u8; 2] = attribute[0..2].try_into().expect("failed to convert");
        let attribute_length: [u8; 2] = attribute[2..4].try_into().expect("failed to convert");
        let attribute_value: Vec<u8> = attribute[4..].try_into().expect("failed to convert");
        let message_attribute = StunMessageAttribute {
            attribute_type,
            length: attribute_length,
            value: attribute_value,
        };
        let requested_message = StunMessage {
            header: message_header,
            attribute: message_attribute,
        };
        println!("requested_message: {:?}", requested_message);

        // RESPONSE

        let response_header = StunMessageHeader {
            message_type: StunMessageType {
                class: StunMessageClass::SuccessResponse,
                method: StunMessageMethod::Binding,
            },
            message_length: [0, 12],
            magic_cookie: (0x2112A442 as u32).to_be_bytes(),
            transaction_id: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11], // TODO
        };

        let xor_mapped_address_type = (0x0020 as u16).to_be_bytes();

        let response_attribute = StunMessageAttribute {
            attribute_type: xor_mapped_address_type,
            length: (8 as u16).to_be_bytes(),
            value: create_xor_mapped_address_and_port(src).to_vec(),
        };
        let response_message = StunMessage {
            header: response_header,
            attribute: response_attribute,
        };
        let res = StunMessage::build(&response_message);

        server_socket.send_to(&res, src)?;
    }
}
