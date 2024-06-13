// SPDX-License-Identifier: GPL-2.0-or-later
//
// June 16 2024, Christian Hopps <chopps@labn.net>
//
// Copyright (C) 2024 LabN Consulting, L.L.C.
//
use std::io::ErrorKind;
use std::io::{Error, Result};
use tokio::io::AsyncReadExt;
use tokio::net::UnixStream;

// -------------
// Mgmt Messages
// -------------

///
/// MGMTd Message Types
///
/// Mgmtd Messages are sent with a simple framing. A 32-bit marker heads the
/// message that indicates the type of message Native or Protobuf currently.
/// Next a 32-bit little-endian length value, followed by `length` octets of
/// message data.
///
#[derive(Debug)]
pub enum MsgType {
    NativeMsg(Vec<u8>),
    ProtobufMsg(()),
}

const MGMT_MSG_MARKER_PROTOBUF: [u8; 4] = [0, 35, 35, 35];
const MGMT_MSG_MARKER_NATIVE: [u8; 4] = [1, 35, 35, 35];

async fn send_data(stream: &UnixStream, data: &[u8]) -> Result<()> {
    let mut to_send = data.len();
    while to_send > 0 {
        stream.writable().await?;

        match stream.try_write(data) {
            Ok(n) => {
                to_send -= n;
            }
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                continue;
            }
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

async fn recv_wait_a(stream: &mut UnixStream, ary: &mut [u8]) -> Result<()> {
    stream.read_exact(ary).await?;
    Ok(())
}

async fn recv_wait_v(stream: &mut UnixStream, sz: usize) -> Result<Vec<u8>> {
    let mut buf = Vec::<u8>::with_capacity(sz);

    // SAFETY: vector is fully initialized by the following read_exact and only
    // returned on success.
    unsafe {
        buf.set_len(sz);
    }

    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

async fn recv_msg(stream: &mut UnixStream) -> Result<MsgType> {
    let mut ary = [0u8; 4];

    // Check what type of message we have given the marker
    recv_wait_a(stream, &mut ary).await?;
    let native_type = if ary == MGMT_MSG_MARKER_NATIVE {
        true
    } else if ary == MGMT_MSG_MARKER_PROTOBUF {
        false
    } else {
        return Err(Error::new(
            ErrorKind::Unsupported,
            "Unknown message framing type",
        ));
    };

    recv_wait_a(stream, &mut ary).await?;
    let msize = u32::from_le_bytes(ary) as usize;
    if msize <= 8 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "Short message (short len)",
        ));
    }

    let vec = recv_wait_v(stream, msize - 8).await?;
    if native_type {
        Ok(MsgType::NativeMsg(vec))
    } else {
        Ok(MsgType::ProtobufMsg(()))
    }
}

pub async fn send_native_msg(stream: &UnixStream, msg: &[u8]) -> Result<()> {
    let sz = u32::to_le_bytes((8 + msg.len()) as u32);

    send_data(stream, &MGMT_MSG_MARKER_NATIVE).await?;
    send_data(stream, &sz).await?;
    send_data(stream, msg).await
}

pub async fn recv_native_msg(stream: &mut UnixStream) -> Result<Vec<u8>> {
    match recv_msg(stream).await? {
        MsgType::NativeMsg(buf) => Ok(buf),
        MsgType::ProtobufMsg(()) => {
            return Err(Error::new(ErrorKind::Unsupported, "Protobuf unsupported"))
        }
    }
}
