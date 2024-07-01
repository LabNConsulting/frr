// SPDX-License-Identifier: GPL-2.0-or-later
// -*- coding: utf-8 -*-s
//
// June 30 2024, Christian Hopps <chopps@labn.net>
//
// Copyright (C) 2024 LabN Consulting, L.L.C.
//
/// Module supporting RESTCONF URLs
use tracing::debug;
use url::Url;
use std::error::Error;

#[derive(Debug)]
pub struct Uri {
    pub url: Url,
    pub segs: Vec<String>,
}

impl Uri {
    pub fn parse(urls: &str) -> Result<Self, Box<dyn Error>> {
        let mut s = Self {
            url: Url::parse(urls)?,
            segs: Vec::<String>::new(),
        };

        if let Some(segs) = s.url.path_segments() {
            for seg in segs {
                s.segs.push(seg.to_string());
            }
        }

        debug!("XXX path vector: {:?}", s.segs);

        Ok(s)
    }
}
