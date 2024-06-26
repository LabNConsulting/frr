// SPDX-License-Identifier: GPL-2.0-or-later
//
// June 13 2024, Christian Hopps <chopps@labn.net>
//
// Copyright (C) 2024 LabN Consulting, L.L.C.
//
use crate::native;
use crate::native::{MgmtMsg, MgmtMsgSessionReq};
// use crate::msg::{array_to_u16, array_to_u32, u32_to_array};
/// Functionality for interacting with FRR MGMTD.
use std::io::{Error, ErrorKind, Result};
use std::sync::atomic::{AtomicU64, Ordering};
use std::os::unix::net::UnixStream;
use tracing::debug;

const MGMTD_SOCK_PATH: &str = "/var/run/frr/mgmtd_fe.sock";

static NEXT_CLIENT_ID: AtomicU64 = AtomicU64::new(154);

fn connect_retry(sock_path: &str) -> Result<UnixStream> {
    debug!("Starting connect-loop to mgmtd.");
    loop {
        match UnixStream::connect(sock_path) {
            Ok(stream) => {
                debug!("Got connected to stream {:?}", stream);
                return Ok(stream);
            }
            Err(e) => {
                if e.kind() == ErrorKind::PermissionDenied {
                    return Err(e);
                };
                debug!("Couldn't connect to mgmtd will retry: {:?}", e);
                std::thread::sleep(std::time::Duration::from_millis(1000));
            }
        }
    }
}

#[derive(Debug)]
pub struct MgmtdSession {
    stream: UnixStream,
    _last_req_id: u64,
}

impl MgmtdSession {
    ///
    /// Create a new connected client session to mgmtd
    ///
    pub fn new() -> Result<Self> {
        let mut s = Self {
            stream: connect_retry(MGMTD_SOCK_PATH)?,
            _last_req_id: 0,
        };
        s.init_session()?;
        Ok(s)
    }

    fn _next_req_id(&mut self) -> u64 {
        self._last_req_id += 1;
        self._last_req_id
    }

    fn init_session(&mut self) -> Result<()> {
        let client_id = NEXT_CLIENT_ID.fetch_add(1, Ordering::SeqCst);
        let msg = MgmtMsgSessionReq::with_values(client_id, "RESTCONF");
        let mut v = native::msg_encode_to_vec(&msg)?;

        // Send the session request message
        v.extend_from_slice("RESTCONF".as_bytes());
        v.push(0);
        native::send_msg(&mut self.stream, &v)?;

        // Wait for the reply
        let mmsg = native::recv_msg(&mut self.stream)?;
        match mmsg {
            MgmtMsg::SessionReply(reply_msg) => reply_msg,
            MgmtMsg::Error(emsg) => return Err(native::msg_to_error(&emsg)),
            _ => return Err(Error::new(ErrorKind::Unsupported, "non-session-reply msg received")),
        };
        Ok(())
    }
}
