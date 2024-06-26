// SPDX-License-Identifier: GPL-2.0-or-later
//
// June 19 2024, Christian Hopps <chopps@labn.net>
//
// Copyright (C) 2024 LabN Consulting, L.L.C.
//

use crate::msg;
use std::io::ErrorKind;
use std::io::{Error, Result};
use std::mem::size_of;
use std::os::unix::net::UnixStream;
use std::str::FromStr;
use tracing::debug;

//
// Native Message Constants
//

/*
 * Message Type Header Code Values
 */
pub const MGMT_MSG_CODE_ERROR: u16 = 0;
pub const MGMT_MSG_CODE_GET_TREE: u16 = 1; // Backend-only non-public API.
pub const MGMT_MSG_CODE_TREE_DATA: u16 = 2;
pub const MGMT_MSG_CODE_GET_DATA: u16 = 3;
pub const MGMT_MSG_CODE_NOTIFY: u16 = 4;
pub const MGMT_MSG_CODE_EDIT: u16 = 5;
pub const MGMT_MSG_CODE_EDIT_REPLY: u16 = 6;
pub const MGMT_MSG_CODE_RPC: u16 = 7;
pub const MGMT_MSG_CODE_RPC_REPLY: u16 = 8;
pub const MGMT_MSG_CODE_NOTIFY_SELECT: u16 = 9;
pub const MGMT_MSG_CODE_SESSION_REQ: u16 = 10;
pub const MGMT_MSG_CODE_SESSION_REPLY: u16 = 11;

/*
 * Datastores
 */
pub const MGMT_MSG_DATASTORE_STARTUP: u8 = 0;
pub const MGMT_MSG_DATASTORE_CANDIDATE: u8 = 1;
pub const MGMT_MSG_DATASTORE_RUNNING: u8 = 2;
pub const MGMT_MSG_DATASTORE_OPERATIONAL: u8 = 3;

/*
 * Formats
 */
pub const MGMT_MSG_FORMAT_XML: u8 = 1;
pub const MGMT_MSG_FORMAT_JSON: u8 = 2;
pub const MGMT_MSG_FORMAT_BINARY: u8 = 3; // non-standard libyang internal format.

// ----------------------------------
// Native Message On Wire Definitions
// ----------------------------------

pub fn decode_cstring(data: &[u8]) -> Result<String> {
    let len = data.len();
    if len == 0 {
        return Ok(String::new());
    }
    if data[len - 1] != 0 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "Msg String Data not NUL terminated",
        ));
    }
    Ok(String::from_utf8_lossy(&data[..len - 1]).to_string())
}

/**
 * struct MgmtMsgHeader - Header common to all native messages.
 *
 * @code: the actual type of the message.
 * @resv: Set to zero, ignore on receive.
 * @vsplit: If a variable section is split in 2, the length of first part.
 * @refer_id: the session, txn, conn, etc, this message is associated with.
 * @req_id: the request this message is for.
 */
#[repr(C)]
#[derive(Debug, Default)]
pub struct MgmtMsgHeader {
    pub code: u16,
    pub resv: u16,
    pub vsplit: u32,
    pub refer_id: u64,
    pub req_id: u64,
}

impl MgmtMsgHeader {
    fn decode(buf: &[u8]) -> Result<Self> {
        Ok(Self {
            code: u16::from_le_bytes(buf[0..2].try_into().unwrap()),
            resv: u16::from_le_bytes(buf[2..4].try_into().unwrap()),
            vsplit: u32::from_le_bytes(buf[4..8].try_into().unwrap()),
            refer_id: u64::from_le_bytes(buf[8..16].try_into().unwrap()),
            req_id: u64::from_le_bytes(buf[16..24].try_into().unwrap()),
        })
    }
}

pub trait FixedPartMessage {
    type Target;
    type FixedTarget;

    fn fixed_size() -> usize {
        size_of::<Self::FixedTarget>()
    }
    fn fixed_cast(&self) -> *const Self::FixedTarget;
    fn new() -> Self::Target;
}

/**
 * struct MgmtMsgError - Common error message.
 *
 * @error: An error value.
 * @errst: Description of error can be 0 length.
 *
 * This common error message can be used for replies for many msg requests
 * (req_id).
 */
#[repr(C)]
#[derive(Debug, Default)]
pub struct MgmtMsgErrorFixed {
    pub header: MgmtMsgHeader,
    pub error: i16,
    pub resv2: [u8; 6],
}

#[derive(Debug, Default)]
pub struct MgmtMsgError {
    pub fixed: MgmtMsgErrorFixed,
    pub errstr: String,
}

impl MgmtMsgError {
    pub fn with_values(client_id: u64, req_id: u64, error: i16, errstr: &str) -> Self {
        Self {
            fixed: MgmtMsgErrorFixed {
                header: MgmtMsgHeader {
                    code: MGMT_MSG_CODE_ERROR,
                    refer_id: client_id,
                    req_id,
                    ..Default::default()
                },
                error,
                ..Default::default()
            },
            errstr: String::from_str(errstr).unwrap(),
        }
    }

    fn decode(buf: &[u8]) -> Result<Self> {
        let off = size_of::<MgmtMsgHeader>();
        let vdata = &buf[Self::fixed_size()..];
        Ok(Self {
            fixed: MgmtMsgErrorFixed {
                header: MgmtMsgHeader::decode(buf)?,
                error: i16::from_le_bytes(buf[off..off + 2].try_into().unwrap()),
                ..Default::default()
            },
            errstr: decode_cstring(vdata)?,
        })
    }
}

impl FixedPartMessage for MgmtMsgError {
    type Target = MgmtMsgError;
    type FixedTarget = MgmtMsgErrorFixed;

    fn new() -> Self::Target {
        Self::Target {
            ..Default::default()
        }
    }
    fn fixed_cast(&self) -> *const Self::FixedTarget {
        &self.fixed as *const Self::FixedTarget
    }
}

/**
 * struct mgmt_msg_tree_data - Message carrying tree data.
 *
 * @partial_error: If the full result could not be returned do to this error.
 * @result_type: ``LYD_FORMAT`` for format of the @result value.
 * @more: if this is a partial return and there will be more coming.
 * @result: The tree data in @result_type format.
 *
 */
#[repr(C)]
#[derive(Debug, Default)]
pub struct MgmtMsgTreeDataFixed {
    pub header: MgmtMsgHeader,
    pub partial_error: i8,
    pub result_type: u8,
    pub more: u8,
    pub resv2: [u8; 5],
}

#[derive(Debug, Default)]
pub struct MgmtMsgTreeData {
    pub fixed: MgmtMsgTreeDataFixed,
    pub result: String,
}

impl MgmtMsgTreeData {
    fn decode(buf: &[u8]) -> Result<Self> {
        let off = size_of::<MgmtMsgHeader>();
        let vdata = &buf[Self::fixed_size()..];
        Ok(Self {
            fixed: MgmtMsgTreeDataFixed {
                header: MgmtMsgHeader::decode(buf)?,
                partial_error: buf[off] as i8,
                result_type: buf[off + 1] as u8,
                more: buf[off + 2] as u8,
                ..Default::default()
            },
            result: decode_cstring(vdata)?,
        })
    }
}

impl FixedPartMessage for MgmtMsgTreeData {
    type Target = MgmtMsgTreeData;
    type FixedTarget = MgmtMsgTreeDataFixed;

    fn new() -> Self::Target {
        Self::Target {
            ..Default::default()
        }
    }
    fn fixed_cast(&self) -> *const Self::FixedTarget {
        &self.fixed as *const Self::FixedTarget
    }
}

/* Flags for get-data request */
pub const GET_DATA_FLAG_STATE: u8 = 0x01; /* include "config false" data */
pub const GET_DATA_FLAG_CONFIG: u8 = 0x02; /* include "config true" data */
pub const GET_DATA_FLAG_EXACT: u8 = 0x04; /* get exact data node instead of the full tree */

/*
 * Modes of reporting default values. Non-default values are always reported.
 * These options reflect "with-defaults" modes as defined in RFC 6243.
 */
pub const GET_DATA_DEFAULTS_EXPLICIT: u8 = 0; /* "explicit" */
pub const GET_DATA_DEFAULTS_TRIM: u8 = 1; /* "trim"  */
pub const GET_DATA_DEFAULTS_ALL: u8 = 2; /* "report-all" */
pub const GET_DATA_DEFAULTS_ALL_ADD_TAG: u8 = 3; /* "report-all-tagged" */

///
/// struct MgmtMsgGetData - frontend get-data request.
///
/// @result_type: ``LYD_FORMAT`` for the returned result.
/// @flags: combination of ``GET_DATA_FLAG_*`` flags.
/// @defaults: one of ``GET_DATA_DEFAULTS_*`` values.
/// @xpath: the query for the data to return.
///
#[repr(C)]
#[derive(Debug, Default)]
pub struct MgmtMsgGetDataFixed {
    pub header: MgmtMsgHeader,
    pub result_type: u8,
    pub flags: u8,
    pub defaults: u8,
    pub datastore: u8,
    pub resv2: [u8; 4],
}

#[derive(Debug, Default)]
pub struct MgmtMsgGetData {
    pub fixed: MgmtMsgGetDataFixed,
    pub xpath: String,
}

impl MgmtMsgGetData {
    pub fn with_values(
        client_id: u64,
        req_id: u64,
        result_type: u8,
        flags: u8,
        defaults: u8,
        datastore: u8,
        xpath: &str,
    ) -> Self {
        Self {
            fixed: MgmtMsgGetDataFixed {
                header: MgmtMsgHeader {
                    code: MGMT_MSG_CODE_GET_DATA,
                    refer_id: client_id,
                    req_id,
                    ..Default::default()
                },
                result_type,
                flags,
                defaults,
                datastore,
                ..Default::default()
            },
            xpath: String::from_str(xpath).unwrap(),
        }
    }

    fn decode(buf: &[u8]) -> Result<Self> {
        let off = size_of::<MgmtMsgHeader>();
        let vdata = &buf[Self::fixed_size()..];
        Ok(Self {
            fixed: MgmtMsgGetDataFixed {
                header: MgmtMsgHeader::decode(buf)?,
                result_type: buf[off] as u8,
                flags: buf[off + 1] as u8,
                defaults: buf[off + 2] as u8,
                datastore: buf[off + 3] as u8,
                ..Default::default()
            },
            xpath: decode_cstring(vdata)?,
        })
    }
}

impl FixedPartMessage for MgmtMsgGetData {
    type Target = MgmtMsgGetData;
    type FixedTarget = MgmtMsgGetDataFixed;

    fn new() -> Self::Target {
        Self::Target {
            ..Default::default()
        }
    }
    fn fixed_cast(&self) -> *const Self::FixedTarget {
        &self.fixed as *const Self::FixedTarget
    }
}

/**
 * struct MgmtMsgSessionReq - Create or delete a front-end session.
 *
 * @refer_id: Zero for create, otherwise the session-id to delete.
 * @req_id: For create will use as client-id.
 * @client_name: For first session request the client name, otherwise empty.
 */
#[repr(C)]
#[derive(Debug, Default)]
pub struct MgmtMsgSessionReqFixed {
    pub header: MgmtMsgHeader,
    pub resv2: [u8; 8],
}

#[derive(Debug, Default)]
pub struct MgmtMsgSessionReq {
    pub fixed: MgmtMsgSessionReqFixed,
    pub client_name: String,
}

impl MgmtMsgSessionReq {
    pub fn with_values(client_id: u64, client_name: &str) -> Self {
        Self {
            fixed: MgmtMsgSessionReqFixed {
                header: MgmtMsgHeader {
                    code: MGMT_MSG_CODE_SESSION_REQ,
                    req_id: client_id,
                    ..Default::default()
                },
                ..Default::default()
            },
            client_name: String::from_str(client_name).unwrap(),
        }
    }

    fn decode(buf: &[u8]) -> Result<Self> {
        let vdata = &buf[Self::fixed_size()..];
        Ok(Self {
            fixed: MgmtMsgSessionReqFixed {
                header: MgmtMsgHeader::decode(buf)?,
                ..Default::default()
            },
            client_name: decode_cstring(vdata)?,
        })
    }
}

impl FixedPartMessage for MgmtMsgSessionReq {
    type Target = MgmtMsgSessionReq;
    type FixedTarget = MgmtMsgSessionReqFixed;

    fn new() -> Self::Target {
        Self::Target {
            ..Default::default()
        }
    }
    fn fixed_cast(&self) -> *const Self::FixedTarget {
        &self.fixed as *const Self::FixedTarget
    }
}

/**
 * struct MgmtMsgSessionReply - Reply to session request message.
 *
 * @created: true if this is a reply to a create request, otherwise 0.
 * @refer_id: The session-id for the action (create or delete) just taken.
 */
#[repr(C)]
#[derive(Debug, Default)]
pub struct MgmtMsgSessionReplyFixed {
    pub header: MgmtMsgHeader,
    pub created: u8,
    pub resv2: [u8; 7],
}

#[derive(Debug, Default)]
pub struct MgmtMsgSessionReply {
    pub fixed: MgmtMsgSessionReplyFixed,
}

impl MgmtMsgSessionReply {
    pub fn with_values(client_id: u64, req_id: u64, created: u8) -> Self {
        Self {
            fixed: MgmtMsgSessionReplyFixed {
                header: MgmtMsgHeader {
                    code: MGMT_MSG_CODE_SESSION_REPLY,
                    refer_id: client_id,
                    req_id,
                    ..Default::default()
                },
                created,
                ..Default::default()
            },
        }
    }
    fn decode(buf: &[u8]) -> Result<Self> {
        let off = size_of::<MgmtMsgHeader>();
        Ok(Self {
            fixed: MgmtMsgSessionReplyFixed {
                header: MgmtMsgHeader::decode(buf)?,
                created: buf[off],
                ..Default::default()
            },
        })
    }
}

impl FixedPartMessage for MgmtMsgSessionReply {
    type Target = MgmtMsgSessionReply;
    type FixedTarget = MgmtMsgSessionReplyFixed;

    fn new() -> Self::Target {
        Self::Target {
            ..Default::default()
        }
    }
    fn fixed_cast(&self) -> *const Self::FixedTarget {
        &self.fixed as *const Self::FixedTarget
    }
}

/**
 * enum MgmtMsg - Enum of all Native Messages
 */
#[derive(Debug)]
pub enum MgmtMsg {
    Error(MgmtMsgError),
    TreeData(MgmtMsgTreeData),
    GetData(MgmtMsgGetData),
    SessionReq(MgmtMsgSessionReq),
    SessionReply(MgmtMsgSessionReply),
}

//
// Native Message Manipulation Functionality
//

pub fn msg_encode_to_vec<T: FixedPartMessage>(msg: &T) -> Result<Vec<u8>> {
    let sz = T::fixed_size();
    let mptr: *const T::FixedTarget = msg.fixed_cast();
    let mut v = vec![0u8; sz];
    // let mut v = Vec::<u8>::with_capacity(sz);

    // SAFETY: We reserve capacity above, and immediately initialize new bytes with the copy.
    unsafe {
        // v.set_len(sz);
        std::ptr::copy_nonoverlapping(mptr as *const u8, v.as_mut_ptr(), sz);
    }
    Ok(v)
}

pub fn mgmt_msg_encode_to_vec(msg: &MgmtMsg) -> Result<Vec<u8>> {
    match msg {
        MgmtMsg::Error(cmsg) => msg_encode_to_vec(cmsg),
        MgmtMsg::TreeData(cmsg) => msg_encode_to_vec(cmsg),
        MgmtMsg::GetData(cmsg) => msg_encode_to_vec(cmsg),
        MgmtMsg::SessionReq(cmsg) => msg_encode_to_vec(cmsg),
        MgmtMsg::SessionReply(cmsg) => msg_encode_to_vec(cmsg),
    }
}

pub fn msg_to_error(msg: &MgmtMsgError) -> Error {
    Error::new(
        ErrorKind::Other,
        format!(
            "Native message error for client-id {} req-id {} error {}",
            msg.fixed.header.refer_id, msg.fixed.header.req_id, msg.fixed.error
        ),
    )
}

pub const fn min_msg_size(code: u16) -> usize {
    match code {
        MGMT_MSG_CODE_ERROR => size_of::<MgmtMsgError>(),
        MGMT_MSG_CODE_TREE_DATA => size_of::<MgmtMsgTreeData>(),
        MGMT_MSG_CODE_GET_DATA => size_of::<MgmtMsgGetData>(),
        MGMT_MSG_CODE_SESSION_REQ => size_of::<MgmtMsgSessionReq>(),
        MGMT_MSG_CODE_SESSION_REPLY => size_of::<MgmtMsgSessionReply>(),
        _ => 0,
    }
}

pub fn msg_decode_from_vec<T>(buf: &[u8]) -> Result<T>
where
    T: FixedPartMessage<Target = T> + Default,
{
    let sz = T::fixed_size();
    let mut x = T::new();
    let xp: *mut T = &mut x;

    // SAFETY: T must be a C struct
    unsafe {
        std::ptr::copy_nonoverlapping(buf.as_ptr(), xp as *mut u8, sz);
    }
    Ok(x)
}

pub fn mgmt_msg_decode_from_vec(buf: &[u8]) -> Result<MgmtMsg> {
    let code = u16::from_le_bytes(buf[0..2].try_into().unwrap());
    let min_size = min_msg_size(code);
    if min_size == 0 {
        return Err(Error::new(
            ErrorKind::Unsupported,
            format!("Unsupported message code {}", code),
        ));
    }
    if buf.len() < min_size {
        return Err(Error::new(ErrorKind::InvalidData, "Short message (msg)"));
    }
    let msg = match code {
        MGMT_MSG_CODE_ERROR => MgmtMsg::Error(MgmtMsgError::decode(buf)?),
        MGMT_MSG_CODE_TREE_DATA => MgmtMsg::TreeData(MgmtMsgTreeData::decode(buf)?),
        MGMT_MSG_CODE_GET_DATA => MgmtMsg::GetData(MgmtMsgGetData::decode(buf)?),
        MGMT_MSG_CODE_SESSION_REQ => MgmtMsg::SessionReq(MgmtMsgSessionReq::decode(buf)?),
        MGMT_MSG_CODE_SESSION_REPLY => MgmtMsg::SessionReply(MgmtMsgSessionReply::decode(buf)?),
        _ => {
            return Err(Error::new(
                ErrorKind::Unsupported,
                format!("Unsupported message code {}", code),
            ));
        }
    };
    Ok(msg)
}

pub fn send_msg(stream: &mut UnixStream, msg: &[u8]) -> Result<()> {
    msg::send_native_msg(stream, msg)
}

pub fn recv_msg(stream: &mut UnixStream) -> Result<MgmtMsg> {
    let buf = msg::recv_native_msg(stream)?;
    if buf.len() < size_of::<MgmtMsgHeader>() {
        return Err(Error::new(ErrorKind::InvalidData, "Short message (hdr)"));
    }
    let native_msg = mgmt_msg_decode_from_vec(&buf)?;

    debug!("Got native message: {:x?}", native_msg);

    Ok(native_msg)
}
