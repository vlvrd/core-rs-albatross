use beserial::{Serialize, SerializeWithLength, Deserialize, DeserializeWithLength, ReadBytesExt, WriteBytesExt};
use consensus::base::primitive::crypto::{PublicKey, Signature};
use network::Protocol;
use network::address::{NetAddress, PeerId};
use std::io;
use std::vec::Vec;

pub enum PeerAddressType {
    Dumb,
    Ws(String, u16),
    Wss(String, u16),
    Rtc,
}

impl PeerAddressType {
    pub fn get_protocol(&self) -> Protocol {
        match self {
            PeerAddressType::Dumb => Protocol::Dumb,
            PeerAddressType::Ws(_, _) => Protocol::Ws,
            PeerAddressType::Wss(_, _) => Protocol::Wss,
            PeerAddressType::Rtc => Protocol::Rtc
        }
    }
}

pub struct PeerAddress {
    ty: PeerAddressType,
    services: u32,
    timestamp: u64,
    net_address: NetAddress,
    public_key: PublicKey,
    distance: u8,
    signature: Signature,
}

impl Serialize for PeerAddress {
    fn serialize<W: WriteBytesExt>(&self, writer: &mut W) -> Result<usize, io::Error> {
        let mut size = 0;
        size += self.ty.get_protocol().serialize(writer)?;
        size += self.services.serialize(writer)?;
        size += self.timestamp.serialize(writer)?;
        size += self.net_address.serialize(writer)?;
        size += self.public_key.serialize(writer)?;
        size += self.distance.serialize(writer)?;
        size += self.signature.serialize(writer)?;
        size += match &self.ty {
            PeerAddressType::Dumb => 0,
            PeerAddressType::Ws(host, port) => host.serialize::<u16, W>(writer)? + port.serialize(writer)?,
            PeerAddressType::Wss(host, port) => host.serialize::<u16, W>(writer)? + port.serialize(writer)?,
            PeerAddressType::Rtc => 0
        };
        return Ok(size);
    }

    fn serialized_size(&self) -> usize {
        let mut size = 0;
        size += self.ty.get_protocol().serialized_size();
        size += self.services.serialized_size();
        size += self.timestamp.serialized_size();
        size += self.net_address.serialized_size();
        size += self.public_key.serialized_size();
        size += self.distance.serialized_size();
        size += self.signature.serialized_size();
        size += match &self.ty {
            PeerAddressType::Dumb => 0,
            PeerAddressType::Ws(host, port) => host.serialized_size::<u16>() + port.serialized_size(),
            PeerAddressType::Wss(host, port) => host.serialized_size::<u16>() + port.serialized_size(),
            PeerAddressType::Rtc => 0
        };
        return size;
    }
}

impl Deserialize for PeerAddress {
    fn deserialize<R: ReadBytesExt>(reader: &mut R) -> Result<Self, io::Error> {
        let protocol: Protocol = Deserialize::deserialize(reader)?;
        let services: u32 = Deserialize::deserialize(reader)?;
        let timestamp: u64 = Deserialize::deserialize(reader)?;
        let net_address: NetAddress = Deserialize::deserialize(reader)?;
        let public_key: PublicKey = Deserialize::deserialize(reader)?;
        let distance: u8 = Deserialize::deserialize(reader)?;
        let signature: Signature = Deserialize::deserialize(reader)?;
        let type_special: PeerAddressType = match protocol {
            Protocol::Dumb => PeerAddressType::Dumb,
            Protocol::Ws => PeerAddressType::Ws(DeserializeWithLength::deserialize::<u16, R>(reader)?, Deserialize::deserialize(reader)?),
            Protocol::Wss => PeerAddressType::Wss(DeserializeWithLength::deserialize::<u16, R>(reader)?, Deserialize::deserialize(reader)?),
            Protocol::Rtc => PeerAddressType::Rtc
        };
        return Ok(PeerAddress{ ty: type_special, services, timestamp, net_address, public_key, distance, signature});
    }
}

impl PeerAddress {
    pub fn verify_signature(&self) -> bool {
        self.public_key.verify(&self.signature, self.get_signature_data().as_slice())
    }

    pub fn as_uri(&self) -> String {
        let peer_id: String = String::from(::hex::encode(&PeerId::from(&self.public_key).0));
        match self.ty {
            PeerAddressType::Dumb => format!("dumb:///{}", peer_id),
            PeerAddressType::Ws(ref host, ref port) => format!("ws:///{}:{}/{}", host, port, peer_id),
            PeerAddressType::Wss(ref host, ref port) => format!("wss:///{}:{}/{}", host, port, peer_id),
            PeerAddressType::Rtc => format!("rtc:///{}", peer_id)
        }
    }

    pub fn get_signature_data(&self) -> Vec<u8> {
        let mut res: Vec<u8> = (self.ty.get_protocol() as u8).serialize_to_vec();
        res.append(&mut self.services.serialize_to_vec());
        res.append(&mut self.timestamp.serialize_to_vec());

        match &self.ty {
            PeerAddressType::Ws(host, port) | PeerAddressType::Wss(host, port) => {
                res.append(&mut host.serialize_to_vec::<u16>());
                res.append(&mut port.serialize_to_vec());
            }
            _ => {}
        };

        return res;
    }
}

impl Deserialize for PeerAddressType {
    fn deserialize<R: ReadBytesExt>(reader: &mut R) -> Result<Self, io::Error> {
        let protocol: Protocol = Deserialize::deserialize(reader)?;
        match protocol {
            Protocol::Dumb => Ok(PeerAddressType::Dumb),
            Protocol::Ws => Ok(PeerAddressType::Ws(DeserializeWithLength::deserialize::<u16, R>(reader)?, Deserialize::deserialize(reader)?)),
            Protocol::Wss => Ok(PeerAddressType::Wss(DeserializeWithLength::deserialize::<u16, R>(reader)?, Deserialize::deserialize(reader)?)),
            Protocol::Rtc => Ok(PeerAddressType::Rtc)
        }
    }
}

impl Serialize for PeerAddressType {
    fn serialize<W: WriteBytesExt>(&self, writer: &mut W) -> Result<usize, io::Error> {
        Ok(match self {
            PeerAddressType::Dumb => Protocol::Dumb.serialize(writer)?,
            PeerAddressType::Ws(host, port) => Protocol::Ws.serialize(writer)? + host.serialize::<u16, W>(writer)? + port.serialize(writer)?,
            PeerAddressType::Wss(host, port) => Protocol::Wss.serialize(writer)? + host.serialize::<u16, W>(writer)? + port.serialize(writer)?,
            PeerAddressType::Rtc => Protocol::Rtc.serialize(writer)?
        })
    }

    fn serialized_size(&self) -> usize {
        Protocol::Dumb.serialized_size() + match self {
            PeerAddressType::Ws(host, port) => host.serialized_size::<u16>() + port.serialized_size(),
            PeerAddressType::Wss(host, port) => host.serialized_size::<u16>() + port.serialized_size(),
            _ => 0
        }
    }
}
