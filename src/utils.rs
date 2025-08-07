#[cfg(unix)]
use tokio::signal::unix::{signal, SignalKind};
use tokio_util::sync::CancellationToken;

pub async fn run_checkers(cancel: CancellationToken) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        let mut stream = signal(SignalKind::hangup())?;
        let gc = cancel.clone();
        tokio::spawn(async move {
            loop {
                stream.recv().await;
                info!("got signal HUP");
                gc.cancel();
            }
        });
    }
    #[cfg(unix)]
    {
        let mut stream = signal(SignalKind::interrupt())?;
        let gc = cancel.clone();
        tokio::spawn(async move {
            loop {
                stream.recv().await;
                info!("got signal INT");
                gc.cancel();
            }
        });
    }
    #[cfg(unix)]
    {
        let mut stream = signal(SignalKind::terminate())?;
        let gc = cancel.clone();
        tokio::spawn(async move {
            loop {
                stream.recv().await;
                info!("got signal TERM");
                gc.cancel();
            }
        });
    }
    #[cfg(windows)]
    {
        let mut stream = tokio::signal::windows::ctrl_break()?;
        let gc = cancel.clone();
        tokio::spawn(async move {
            loop {
                stream.recv().await;
                info!("got ctrl_break");
                gc.cancel();
            }
        });
        let mut stream = tokio::signal::windows::ctrl_close()?;
        let gc = cancel.clone();
        tokio::spawn(async move {
            loop {
                stream.recv().await;
                info!("got ctrl_close");
                gc.cancel();
            }
        });
        let mut stream = tokio::signal::windows::ctrl_logoff()?;
        let gc = cancel.clone();
        tokio::spawn(async move {
            loop {
                stream.recv().await;
                info!("got ctrl_close");
                gc.cancel();
            }
        });
        let mut stream = tokio::signal::windows::ctrl_shutdown()?;
        let gc = cancel.clone();
        tokio::spawn(async move {
            loop {
                stream.recv().await;
                info!("got ctrl_close");
                gc.cancel();
            }
        });
    }
    Ok(())
}
