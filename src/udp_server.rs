use crate::util;
use anyhow::{bail, ensure, Result};
use std::convert::TryInto;
use std::net::{SocketAddr, UdpSocket};
use std::str;

const MAGIC_COOKIE: u32 = 0x2112A442;

fn create_xor_mapped_address_and_port(address_port: SocketAddr) -> Result<[u8; 8]> {
    let fix0: u8 = 0x0;
    let family_ipv4: u8 = 0x01;

    let address_port_str = address_port.to_string();
    let address_port_vec: Vec<&str> = address_port_str.split(':').collect();
    let address = address_port_vec[0];
    let port_int: u16 = address_port_vec[1].parse()?;

    let magic_bytes: [u8; 4] = MAGIC_COOKIE.to_be_bytes();
    let magic_bytes_16bits: [u8; 2] = magic_bytes[0..2].try_into()?;
    let magic_16bits = u16::from_be_bytes(magic_bytes_16bits);

    let xor_port_u16: u16 = port_int ^ magic_16bits;
    let xor_port = xor_port_u16.to_be_bytes();

    let address_vec: Vec<&str> = address.split('.').collect();
    let address_vec_int: Vec<u8> = address_vec
        .iter()
        .flat_map(|address| address.parse())
        .collect();
    let address_array: [u8; 4] = util::vec_to_array(address_vec_int);
    let address_int: u32 = u32::from_be_bytes(address_array);
    let xor_address_u32 = address_int ^ MAGIC_COOKIE;
    let xor_address = xor_address_u32.to_be_bytes();

    return Ok([
        fix0,
        family_ipv4,
        xor_port[0],
        xor_port[1],
        xor_address[0],
        xor_address[1],
        xor_address[2],
        xor_address[3],
    ]);
}

#[derive(Debug)]
enum StunMessageClass {
    Request,
    Indication,
    SuccessResponse,
    ErrorResponse,
}

impl StunMessageClass {
    fn str_to_class(str: &str) -> Result<StunMessageClass> {
        if str == "00" {
            Ok(StunMessageClass::Request)
        } else if str == "01" {
            Ok(StunMessageClass::Indication)
        } else if str == "10" {
            Ok(StunMessageClass::SuccessResponse)
        } else if str == "11" {
            Ok(StunMessageClass::ErrorResponse)
        } else {
            bail!("STUN message class NG")
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
impl StunMessageMethod {
    fn int_to_class(i: u8) -> Result<StunMessageMethod> {
        if i == 1 {
            Ok(StunMessageMethod::Binding)
        } else if i == 3 {
            Ok(StunMessageMethod::Allocate)
        } else if i == 4 {
            Ok(StunMessageMethod::Refresh)
        } else if i == 6 {
            Ok(StunMessageMethod::Send)
        } else if i == 7 {
            Ok(StunMessageMethod::Data)
        } else if i == 8 {
            Ok(StunMessageMethod::CreatePermission)
        } else if i == 9 {
            Ok(StunMessageMethod::ChannelBind)
        } else {
            bail!("STUN message class NG")
        }
    }
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
    fn parse(buffer: &[u8; 1024]) -> Result<StunMessage> {
        let header = &buffer[0..20];
        let attribute = &buffer[20..];

        let message_type_slice: Vec<_> =
            header[0..2].iter().map(|x| format!("{:0>8b}", x)).collect();
        let mut message_type = message_type_slice.concat();

        let c0 = message_type.remove(11);
        let c1 = message_type.remove(7);
        let message_class = format!("{}{}", c0, c1);
        let class = StunMessageClass::str_to_class(&*message_class)?;

        let message_type_int = u8::from_str_radix(&*message_type, 2)?;
        let method = StunMessageMethod::int_to_class(message_type_int)?;
        let message_type = StunMessageType { class, method };

        let message_length_2_bytes: [u8; 2] = header[2..4].try_into()?;

        let magic_cookie_4_bytes: [u8; 4] = header[4..8].try_into()?;
        ensure!(
            magic_cookie_4_bytes == MAGIC_COOKIE.to_be_bytes(),
            "magic cookie NG"
        );

        let transaction_id_12_bytes: [u8; 12] =
            header[8..20].try_into().expect("failed to convert");

        let message_header = StunMessageHeader {
            message_type,
            message_length: message_length_2_bytes,
            magic_cookie: magic_cookie_4_bytes,
            transaction_id: transaction_id_12_bytes,
        };

        let attribute_type: [u8; 2] = attribute[0..2].try_into()?;
        let attribute_length: [u8; 2] = attribute[2..4].try_into()?;
        let attribute_value: Vec<u8> = attribute[4..].try_into()?;
        let message_attribute = StunMessageAttribute {
            attribute_type,
            length: attribute_length,
            value: attribute_value,
        };
        return Ok(StunMessage {
            header: message_header,
            attribute: message_attribute,
        });
    }
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

fn receive_and_send(server_socket: &UdpSocket) -> Result<()> {
    let mut buffer = [0u8; 1024];
    let (_size, src) = server_socket.recv_from(&mut buffer)?;
    let requested_message = StunMessage::parse(&buffer)?;
    println!("requested_message: {:?}", requested_message);

    let xor_mapped_address = create_xor_mapped_address_and_port(src)?;

    if matches!(
        requested_message.header.message_type.class,
        StunMessageClass::Request
    ) && matches!(
        requested_message.header.message_type.method,
        StunMessageMethod::Binding
    ) {
        let response_header = StunMessageHeader {
            message_type: StunMessageType {
                class: StunMessageClass::SuccessResponse,
                method: StunMessageMethod::Binding,
            },
            message_length: [0, 12],
            magic_cookie: (MAGIC_COOKIE as u32).to_be_bytes(),
            transaction_id: requested_message.header.transaction_id,
        };

        let xor_mapped_address_type = (0x0020 as u16).to_be_bytes();
        let response_attribute = StunMessageAttribute {
            attribute_type: xor_mapped_address_type,
            length: (8 as u16).to_be_bytes(),
            value: xor_mapped_address.to_vec(),
        };
        let response_message = StunMessage {
            header: response_header,
            attribute: response_attribute,
        };
        let res = StunMessage::build(&response_message);

        server_socket.send_to(&res, src)?;
    }
    Ok(())
}

pub fn serve(address_port: &str) -> Result<()> {
    let server_socket = UdpSocket::bind(address_port)?;
    loop {
        let _ = receive_and_send(&server_socket).map_err(|e| println!("{:#?}", e));
    }
}
