pub mod event;

use anyhow::Result;
use notify::{Event, EventKind, RecursiveMode, Watcher};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use tokio::sync::broadcast;
use tracing::{debug, warn};

pub use event::TraceEvent;

/// Consumer for Strix v0.8.3 OpenTelemetry JSONL traces.
///
/// Strix writes traces to `~/.strix/runs/<run-id>/traces.jsonl`.
/// This consumer watches that file and emits parsed TraceEvents to
/// an async broadcast channel, so Lancer UI and the findings correlator
/// can react in real time.
pub struct TraceConsumer {
    trace_path: PathBuf,
    tx: broadcast::Sender<TraceEvent>,
}

impl TraceConsumer {
    pub fn new(trace_path: impl AsRef<Path>) -> (Self, broadcast::Receiver<TraceEvent>) {
        let (tx, rx) = broadcast::channel(512);
        (
            TraceConsumer {
                trace_path: trace_path.as_ref().to_path_buf(),
                tx,
            },
            rx,
        )
    }

    /// Start watching the traces.jsonl file.
    /// Runs until the file is deleted or the process exits.
    pub async fn run(self) -> Result<()> {
        let (fs_tx, fs_rx) = mpsc::channel::<notify::Result<Event>>();

        let mut watcher = notify::recommended_watcher(fs_tx)?;
        if let Some(parent) = self.trace_path.parent() {
            watcher.watch(parent, RecursiveMode::NonRecursive)?;
        }

        // Read any pre-existing content
        let mut byte_offset: u64 = 0;
        if self.trace_path.exists() {
            byte_offset = self.drain_new_lines(&self.trace_path, byte_offset)?;
        }

        for res in fs_rx {
            match res {
                Ok(event) => {
                    if matches!(event.kind, EventKind::Modify(_) | EventKind::Create(_)) {
                        let path_matches = event
                            .paths
                            .iter()
                            .any(|p| p.file_name() == self.trace_path.file_name());

                        if path_matches {
                            match self.drain_new_lines(&self.trace_path, byte_offset) {
                                Ok(new_offset) => byte_offset = new_offset,
                                Err(e) => warn!("Error reading trace file: {e}"),
                            }
                        }
                    }
                }
                Err(e) => warn!("FS watch error: {e}"),
            }
        }

        Ok(())
    }

    fn drain_new_lines(&self, path: &Path, from_byte: u64) -> Result<u64> {
        use std::io::{Read, Seek, SeekFrom};

        let mut file = std::fs::File::open(path)?;
        file.seek(SeekFrom::Start(from_byte))?;

        let mut buf = String::new();
        file.read_to_string(&mut buf)?;

        let bytes_read = buf.len() as u64;

        for line in buf.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            match serde_json::from_str::<TraceEvent>(line) {
                Ok(event) => {
                    debug!("Trace event: {:?}", event.name);
                    let _ = self.tx.send(event);
                }
                Err(e) => debug!("Skipping unparseable trace line: {e}"),
            }
        }

        Ok(from_byte + bytes_read)
    }
}
