// SPDX-License-Identifier: GPL-2.0-or-later
//
// June 8 2024, Christian Hopps <chopps@labn.net>
//
// Copyright (C) 2024 LabN Consulting, L.L.C.
//

pub mod cbor;
pub mod cstruct;

fn first_main() {
    cbor::test_cbor();
    cstruct::test_cstruct();
}

use axum::{response::Html, routing::get, Router};
// use tower_http::{classify::ServerErrorsFailureClass, trace::TraceLayer};
use tracing::Level;
use tracing_subscriber::FmtSubscriber;
// use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use std::{error::Error, io};

use tracing::{debug, error, info, span, warn};

#[tracing::instrument]
pub fn shave(yak: usize) -> Result<(), Box<dyn Error + 'static>> {
    // this creates an event at the DEBUG level with two fields:
    // - `excitement`, with the key "excitement" and the value "yay!"
    // - `message`, with the key "message" and the value "hello! I'm gonna shave a yak."
    //
    // unlike other fields, `message`'s shorthand initialization is just the string itself.
    debug!(excitement = "yay!", "hello! I'm gonna shave a yak.");
    if yak > 1 {
        warn!("could not locate yak!");
        // note that this is intended to demonstrate `tracing`'s features, not idiomatic
        // error handling! in a library or application, you should consider returning
        // a dedicated `YakError`. libraries like snafu or thiserror make this easy.
        return Err(io::Error::new(io::ErrorKind::Other, "shaving yak failed!").into());
    } else {
        debug!("yak shaved successfully");
    }
    Ok(())
}

pub fn shave_all(yaks: usize) -> usize {
    // Constructs a new span named "shaving_yaks" at the TRACE level,
    // and a field whose key is "yaks". This is equivalent to writing:
    //
    // let span = span!(Level::TRACE, "shaving_yaks", yaks = yaks);
    //
    // local variables (`yaks`) can be used as field values
    // without an assignment, similar to struct initializers.
    let _span_ = span!(Level::TRACE, "shaving_yaks", yaks).entered();

    info!("shaving yaks");

    let mut yaks_shaved = 0;
    for yak in 1..=yaks {
        let res = shave(yak);
        debug!(yak, shaved = res.is_ok());

        if let Err(ref error) = res {
            // Like spans, events can also use the field initialization shorthand.
            // In this instance, `yak` is the field being initalized.
            error!(yak, error = error.as_ref(), "failed to shave yak!");
        } else {
            yaks_shaved += 1;
        }
        debug!(yaks_shaved);
    }

    yaks_shaved
}

// use std::time::Duration;
// use tracing::{info_span, Level, Span};
// use axum::{
//     body::Bytes,
//     extract::MatchedPath,
//     http::{HeaderMap, Request},
//     response::{Html, Response},
// .route()
// .layer(
//         TraceLayer::new_for_http()
//             .make_span_with(|request: &Request<_>| {
//                 // Log the matched route's path (with placeholders not filled in).
//                 // Use request.uri() or OriginalUri if you want the real path.
//                 let matched_path = request
//                     .extensions()
//                     .get::<MatchedPath>()
//                     .map(MatchedPath::as_str);

//                 info_span!(
//                     "http_request",
//                     method = ?request.method(),
//                     matched_path,
//                     some_other_field = tracing::field::Empty,
//                 )
//             })
//             .on_request(|_request: &Request<_>, _span: &Span| {
//                 // You can use `_span.record("some_other_field", value)` in one of these
//                 // closures to attach a value to the initially empty field in the info_span
//                 // created above.
//                 debug!("on request")
//             })
//             .on_response(|_response: &Response, _latency: Duration, _span: &Span| {
//                 // ...
//                 debug!("on response")
//             })
//             .on_body_chunk(|_chunk: &Bytes, _latency: Duration, _span: &Span| {
//                 // ...
//                 debug!("on body chunk")
//             })
//             .on_eos(
//                 |_trailers: Option<&HeaderMap>, _stream_duration: Duration, _span: &Span| {
//                     // ...
//                 debug!("on body eos")
//                 },
//             )
//             .on_failure(
//                 |_error: ServerErrorsFailureClass, _latency: Duration, _span: &Span| {
//                     // ...
//                 debug!("on failure")
//                 },
//             ),
//     );

#[tokio::main]
async fn main() {
    first_main();

    /*
     * Enable some logging
     */
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::TRACE)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    shave_all(2);

    /*
     * Create the axum web app using Router
     */
    let app = Router::new().route("/", get(handler));
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();

    /*
     * run the app (async executor loop)
     */
    tracing::debug!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}

async fn handler() -> Html<&'static str> {
    tracing::debug!("Building hello world response");
    Html("<h1>Hello, World!</h1>")
}
