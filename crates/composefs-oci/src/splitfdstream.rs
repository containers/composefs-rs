//! Client for importing container layers from a splitfdstream server.
//!
//! Implements the JSON-RPC 2.0 + SCM_RIGHTS protocol used by the Go
//! `jsonrpc-fdpass-go` transport.  Each JSON message carries an `"fds"` field
//! that tells how many file descriptors accompany it via ancillary data.
//! FDs are batched (max 8 per sendmsg); overflow batches arrive as `"fds"`
//! notifications.

use std::fs::File;
use std::io::{Cursor, IoSliceMut, Read, Write};
use std::mem::MaybeUninit;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use rustix::net::{RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags};

use composefs::fsverity::FsVerityHashValue;
use composefs::repository::Repository;
use splitfdstream::{Chunk, SplitfdstreamReader};

use crate::skopeo::TAR_LAYER_CONTENT_TYPE;

// --- Transport layer (matches Go jsonrpc-fdpass-go) ---

/// Read buffer size for recvmsg data (Go: ReadBufferSize).
const READ_BUFFER_SIZE: usize = 4096;

/// Persistent receive state, equivalent to the Go `Receiver` struct.
struct Receiver<'a> {
    socket: &'a UnixStream,
    buffer: Vec<u8>,
    fd_queue: Vec<OwnedFd>,
}

impl<'a> Receiver<'a> {
    fn new(socket: &'a UnixStream) -> Self {
        Self {
            socket,
            buffer: Vec::new(),
            fd_queue: Vec::new(),
        }
    }

    /// Read more data (and possibly FDs) from the socket.
    /// Mirrors Go `Receiver.readMoreData` / `recvWithFDs`.
    fn read_more_data(&mut self) -> Result<usize> {
        let mut buf = [0u8; READ_BUFFER_SIZE];
        let mut iov = [IoSliceMut::new(&mut buf)];

        // Ancillary buffer sized for 8 file descriptors (Go: MaxFDsPerMessage).
        let mut cmsg_space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(8))];
        let mut cmsg_buffer = RecvAncillaryBuffer::new(&mut cmsg_space);

        let result = rustix::net::recvmsg(
            self.socket,
            &mut iov,
            &mut cmsg_buffer,
            RecvFlags::CMSG_CLOEXEC,
        )
        .context("recvmsg")?;

        let bytes = result.bytes;
        if bytes > 0 {
            self.buffer.extend_from_slice(&buf[..bytes]);
        }

        for msg in cmsg_buffer.drain() {
            if let RecvAncillaryMessage::ScmRights(fds) = msg {
                self.fd_queue.extend(fds);
            }
        }

        Ok(bytes)
    }

    /// Receive the next complete JSON-RPC message with its file descriptors.
    /// Mirrors Go `Receiver.Receive` + `tryParseMessage`.
    fn receive(&mut self) -> Result<(serde_json::Value, Vec<OwnedFd>)> {
        loop {
            // Try to parse a complete JSON value from buffered data.
            if !self.buffer.is_empty() {
                let mut stream = serde_json::Deserializer::from_slice(&self.buffer)
                    .into_iter::<serde_json::Value>();
                match stream.next() {
                    Some(Ok(value)) => {
                        let consumed = stream.byte_offset();
                        self.buffer.drain(..consumed);

                        // Dequeue FDs indicated by the "fds" field.
                        let fd_count =
                            value.get("fds").and_then(|v| v.as_u64()).unwrap_or(0) as usize;

                        // FDs may arrive across multiple recvmsg calls on
                        // SOCK_STREAM; keep reading until we have enough.
                        while self.fd_queue.len() < fd_count {
                            let n = self.read_more_data()?;
                            if n == 0 && self.fd_queue.len() < fd_count {
                                bail!(
                                    "connection closed: message expects {} FDs \
                                     but only {} received",
                                    fd_count,
                                    self.fd_queue.len()
                                );
                            }
                        }

                        let fds = self.fd_queue.drain(..fd_count).collect();
                        return Ok((value, fds));
                    }
                    Some(Err(e)) if e.is_eof() => { /* incomplete, need more data */ }
                    Some(Err(e)) => return Err(e).context("JSON framing error"),
                    None => { /* empty, need more data */ }
                }
            }

            let n = self.read_more_data()?;
            if n == 0 {
                bail!("connection closed before complete message received");
            }
        }
    }
}

// --- Object storage helpers ---

fn store_fd_to_repo<ObjectID: FsVerityHashValue>(
    repo: &Repository<ObjectID>,
    fd: OwnedFd,
    size: u64,
) -> Result<ObjectID> {
    let tmpfile = repo.create_object_tmpfile()?;
    let mut src = File::from(fd);
    let mut dst = File::from(tmpfile);
    std::io::copy(&mut src, &mut dst).context("copying to repository")?;
    repo.finalize_object_tmpfile(dst, size)
}

// --- Public entry point ---

/// Import a container layer from a splitfdstream server into the repository.
///
/// Receives file descriptors from the server and stores each one to the
/// repository immediately (then closes it) to avoid hitting the per-process
/// file descriptor limit.
pub fn import_from_splitfdstream<ObjectID: FsVerityHashValue>(
    repo: &Arc<Repository<ObjectID>>,
    socket_path: impl AsRef<Path>,
    diff_id: &str,
    layer_id: Option<&str>,
    parent_id: Option<&str>,
    reference: Option<&str>,
) -> Result<ObjectID> {
    let effective_layer_id = layer_id.unwrap_or(diff_id);
    let socket =
        UnixStream::connect(socket_path.as_ref()).context("connecting to splitfdstream server")?;

    // Build request JSON.
    let mut params = serde_json::json!({ "layerId": effective_layer_id });
    if let Some(pid) = parent_id {
        params["parentId"] = serde_json::json!(pid);
    }
    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "GetSplitFDStream",
        "params": params,
        "id": 1
    });

    let request_bytes = serde_json::to_vec(&request).context("serializing request")?;
    (&socket)
        .write_all(&request_bytes)
        .context("writing request")?;

    let mut receiver = Receiver::new(&socket);

    // Receive the initial response.
    let (resp_value, initial_fds) = receiver.receive().context("receiving response")?;

    if let Some(err) = resp_value.get("error") {
        let msg = err
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("unknown error");
        bail!("splitfdstream server error: {msg}");
    }

    let result = resp_value
        .get("result")
        .context("missing 'result' in response")?;
    let total_fds = result
        .get("totalFDs")
        .and_then(|v| v.as_u64())
        .context("missing 'totalFDs' in result")? as usize;

    // Process FDs as they arrive: store content FDs to the repo immediately
    // so we don't hold hundreds of open file descriptors (which would exceed
    // the per-process rlimit).
    //
    // allFDs[0] is a memfd with the stream data; allFDs[1:] are content FDs.
    let mut stored_objects: Vec<(ObjectID, u64)> = Vec::new();
    let mut stream_data: Option<Vec<u8>> = None;
    let mut fds_processed: usize = 0;

    let process_fd = |fd: OwnedFd,
                      fds_processed: &mut usize,
                      stream_data: &mut Option<Vec<u8>>,
                      stored_objects: &mut Vec<(ObjectID, u64)>|
     -> Result<()> {
        if *fds_processed == 0 {
            let mut file = File::from(fd);
            let mut data = Vec::new();
            file.read_to_end(&mut data)
                .context("reading stream data from memfd")?;
            *stream_data = Some(data);
        } else {
            let stat = rustix::fs::fstat(&fd).context("fstat on received fd")?;
            let size = stat.st_size as u64;
            let object_id =
                store_fd_to_repo(repo, fd, size).context("storing fd to repository")?;
            stored_objects.push((object_id, size));
        }
        *fds_processed += 1;
        Ok(())
    };

    // Process the initial batch.
    for fd in initial_fds {
        process_fd(
            fd,
            &mut fds_processed,
            &mut stream_data,
            &mut stored_objects,
        )?;
    }

    // Receive follow-up "fds" notification batches until we have all FDs.
    while fds_processed < total_fds {
        let (_notif, batch_fds) = receiver.receive().context("receiving fd batch")?;
        for fd in batch_fds {
            process_fd(
                fd,
                &mut fds_processed,
                &mut stream_data,
                &mut stored_objects,
            )?;
        }
    }

    let stream_data = stream_data.context("no stream data received (0 FDs)")?;

    // Parse the splitfdstream and build a composefs splitstream.
    let content_identifier = crate::layer_identifier(diff_id);
    repo.ensure_stream(
        &content_identifier,
        TAR_LAYER_CONTENT_TYPE,
        |writer| {
            let mut reader = SplitfdstreamReader::new(Cursor::new(&stream_data));
            while let Some(chunk) = reader.next_chunk().context("reading splitfdstream chunk")? {
                match chunk {
                    Chunk::Inline(data) => {
                        writer.write_inline(data);
                    }
                    Chunk::External(fd_index) => {
                        let idx = fd_index as usize;
                        if idx >= stored_objects.len() {
                            bail!(
                                "splitfdstream references fd index {idx} \
                                 but only {} content fds received",
                                stored_objects.len()
                            );
                        }
                        let (ref object_id, size) = stored_objects[idx];
                        writer.add_external_size(size);
                        writer.write_reference(object_id.clone())?;
                    }
                }
            }
            Ok(())
        },
        reference,
    )
}
