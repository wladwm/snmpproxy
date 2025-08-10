extern crate bytes;
extern crate clap;
extern crate futures;
extern crate futures_util;
extern crate pretty_env_logger;
extern crate snmp;
extern crate tokio;
extern crate tokio_util;
#[macro_use]
extern crate log;
#[macro_use]
extern crate anyhow;
use anyhow::Result;
use clap::Parser;
#[cfg(any(unix, target_os = "wasi"))]
use std::os::fd::{FromRawFd, IntoRawFd, RawFd};
#[cfg(unix)]
use tokio::signal::unix::{signal, SignalKind};

use std::sync::Arc;

use crate::proxydispatch::SNMPProxyDispatcher;
mod config;
mod hostdata;
mod intercept_socket;
mod proxydispatch;
mod spoof_socket;
mod statistics;
mod utils;
mod value;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    pretty_env_logger::init_timed();
    let args = config::Config::parse();
    let cancel = tokio_util::sync::CancellationToken::new();
    utils::run_checkers(cancel.clone()).await?;
    let cfg = Arc::new(args);
    let dsp = Arc::new(SNMPProxyDispatcher::new(cfg.clone(), cancel.clone()).await?);
    let cnc = cancel.clone();
    let (tx, mut rx) = tokio::sync::mpsc::channel::<intercept_socket::Packet>(100);
    let dspc = dsp.clone();
    let png1 = tokio::spawn(async move {
        while let Some(pck) = tokio::select! {
            r = rx.recv() => r,
            _ = cnc.cancelled() => {
                return
            }
        } {
            if let Err(e) = dspc
                .clone()
                .process_packet(pck.body, pck.from, pck.to)
                .await
            {
                error!("process_packet error {:?}", e);
            }
        }
    });
    #[cfg(unix)]
    {
        let dspc = dsp.clone();
        let mut stream = signal(SignalKind::user_defined1())?;
        let cnc = cancel.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = stream.recv() => {},
                    _ = cnc.cancelled() => {
                        return ;
                    }
                };
                info!("got signal USR1");
                if let Err(e) = dspc.clone().save_stats().await {
                    error!("Error saving statistics: {:?}", e);
                }
            }
        });
    }
    {
        let dspc = dsp.clone();
        let cnc = cancel.clone();
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
        interval.tick().await;
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = interval.tick() => {},
                    _ = cnc.cancelled() => {
                        return ;
                    }
                };
                if let Err(e) = dspc.clone().save_stats().await {
                    error!("Error saving statistics: {:?}", e);
                }
            }
        });
    }
    let rcv = tokio::task::spawn_blocking(move || {
        intercept_socket::recv_loop(cancel, tx, &cfg.intercept)
    });
    if let Err(e) = rcv.await? {
        error!("recv_loop error {:?}", e);
    }
    if let Err(e) = png1.await {
        error!("handler error {:?}", e);
    }
    Ok(())
}
