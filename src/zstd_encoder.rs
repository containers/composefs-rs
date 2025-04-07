use std::{
    cmp::Reverse,
    collections::BinaryHeap,
    io::{self, Write},
};

use sha2::{Digest, Sha256};

use anyhow::{bail, Context, Result};
use zstd::Encoder;

use crate::{
    fsverity::Sha256HashValue,
    repository::Repository,
    splitstream::{
        DigestMap, EnsureObjectMessages, FinishMessage, ResultChannelSender,
        SplitStreamWriterSenderData, WriterMessages, WriterMessagesData,
    },
};

pub(crate) struct ZstdWriter {
    writer: zstd::Encoder<'static, Vec<u8>>,
    repository: Repository,
    pub(crate) sha256_builder: Option<(Sha256, Sha256HashValue)>,
    mode: WriterMode,
}

pub(crate) struct MultiThreadedState {
    last: usize,
    heap: BinaryHeap<Reverse<WriterMessagesData>>,
    final_sha: Option<Sha256HashValue>,
    final_message: Option<FinishMessage>,
    object_sender: crossbeam::channel::Sender<EnsureObjectMessages>,
    final_result_sender: ResultChannelSender,
}

pub(crate) enum WriterMode {
    SingleThreaded,
    MultiThreaded(MultiThreadedState),
}

pub(crate) struct MultipleZstdWriters {
    writers: Vec<ZstdWriter>,
    final_result_sender: ResultChannelSender,
}

impl MultipleZstdWriters {
    pub fn new(
        sha256: Vec<Sha256HashValue>,
        repository: Repository,
        object_sender: crossbeam::channel::Sender<EnsureObjectMessages>,
        final_result_sender: ResultChannelSender,
    ) -> Self {
        Self {
            final_result_sender: final_result_sender.clone(),

            writers: sha256
                .iter()
                .map(|sha| {
                    ZstdWriter::new_threaded(
                        Some(*sha),
                        None,
                        repository.try_clone().unwrap(),
                        object_sender.clone(),
                        final_result_sender.clone(),
                    )
                })
                .collect(),
        }
    }

    pub fn recv_data(
        mut self,
        enc_chan_recvr: crossbeam::channel::Receiver<WriterMessages>,
        layer_num_start: usize,
        layer_num_end: usize,
    ) -> Result<()> {
        assert!(layer_num_end >= layer_num_start);

        let total_writers = self.writers.len();

        // layers_to_writers[layer_num] = writer_idx
        // Faster than a hash map
        let mut layers_to_writers: Vec<usize> = vec![0; layer_num_end];

        for (idx, i) in (layer_num_start..layer_num_end).enumerate() {
            layers_to_writers[i] = idx
        }

        let mut finished_writers = 0;

        while let Ok(data) = enc_chan_recvr.recv() {
            let layer_num = match &data {
                WriterMessages::WriteData(d) => d.object_data.layer_num,
                WriterMessages::Finish(d) => d.layer_num,
            };

            assert!(layer_num >= layer_num_start && layer_num <= layer_num_end);

            match self.writers[layers_to_writers[layer_num]].handle_received_data(data) {
                Ok(finished) => {
                    if finished {
                        finished_writers += 1
                    }
                }

                Err(e) => self
                    .final_result_sender
                    .send(Err(e))
                    .context("Failed to send result on channel")?,
            }

            if finished_writers == total_writers {
                break;
            }
        }

        Ok(())
    }
}

impl ZstdWriter {
    pub fn new_threaded(
        sha256: Option<Sha256HashValue>,
        refs: Option<DigestMap>,
        repository: Repository,
        object_sender: crossbeam::channel::Sender<EnsureObjectMessages>,
        final_result_sender: ResultChannelSender,
    ) -> Self {
        Self {
            writer: ZstdWriter::instantiate_writer(refs),
            repository,
            sha256_builder: sha256.map(|x| (Sha256::new(), x)),

            mode: WriterMode::MultiThreaded(MultiThreadedState {
                final_sha: None,
                last: 0,
                heap: BinaryHeap::new(),
                final_message: None,
                object_sender,
                final_result_sender,
            }),
        }
    }

    pub fn new(
        sha256: Option<Sha256HashValue>,
        refs: Option<DigestMap>,
        repository: Repository,
    ) -> Self {
        Self {
            writer: ZstdWriter::instantiate_writer(refs),
            repository,
            sha256_builder: sha256.map(|x| (Sha256::new(), x)),
            mode: WriterMode::SingleThreaded,
        }
    }

    fn get_state(&self) -> &MultiThreadedState {
        let WriterMode::MultiThreaded(state) = &self.mode else {
            panic!("`get_state` called on a single threaded writer")
        };

        return state;
    }

    fn get_state_mut(&mut self) -> &mut MultiThreadedState {
        let WriterMode::MultiThreaded(state) = &mut self.mode else {
            panic!("`get_state_mut` called on a single threaded writer")
        };

        return state;
    }

    fn instantiate_writer(refs: Option<DigestMap>) -> zstd::Encoder<'static, Vec<u8>> {
        let mut writer = zstd::Encoder::new(vec![], 0).unwrap();

        match refs {
            Some(DigestMap { map }) => {
                writer.write_all(&(map.len() as u64).to_le_bytes()).unwrap();

                for ref entry in map {
                    writer.write_all(&entry.body).unwrap();
                    writer.write_all(&entry.verity).unwrap();
                }
            }

            None => {
                writer.write_all(&0u64.to_le_bytes()).unwrap();
            }
        }

        return writer;
    }

    pub(crate) fn write_fragment(&mut self, size: usize, data: &[u8]) -> Result<()> {
        self.writer.write_all(&(size as u64).to_le_bytes())?;
        Ok(self.writer.write_all(data)?)
    }

    pub(crate) fn update_sha(&mut self, data: &[u8]) {
        if let Some((sha256, ..)) = &mut self.sha256_builder {
            sha256.update(&data);
        }
    }

    /// Writes all the data in `inline_content`, updating the internal SHA
    pub(crate) fn flush_inline(&mut self, inline_content: &Vec<u8>) -> Result<()> {
        if inline_content.is_empty() {
            return Ok(());
        }

        self.update_sha(inline_content);

        self.write_fragment(inline_content.len(), &inline_content)?;

        Ok(())
    }

    /// Keeps popping from the heap until it reaches the message with the largest seq_num, n,
    /// given we have every message with seq_num < n
    fn write_message(&mut self) -> Result<()> {
        loop {
            // Gotta keep lifetime of the destructring inside the loop
            let state = self.get_state_mut();

            let Some(data) = state.heap.peek() else {
                break;
            };

            if data.0.object_data.seq_num != state.last {
                break;
            }

            let data = state.heap.pop().unwrap();
            state.last += 1;

            self.flush_inline(&data.0.object_data.inline_content)?;

            if let Some((sha256, ..)) = &mut self.sha256_builder {
                sha256.update(data.0.object_data.external_data);
            }

            self.write_fragment(0, &data.0.digest)?;
        }

        let final_msg = self.get_state_mut().final_message.take();

        if let Some(final_msg) = final_msg {
            // Haven't received all the messages so we reset the final_message field
            if self.get_state().last < final_msg.total_msgs {
                self.get_state_mut().final_message = Some(final_msg);
                return Ok(());
            }

            let sha = self.handle_final_message(final_msg).unwrap();
            self.get_state_mut().final_sha = Some(sha);
        }

        Ok(())
    }

    fn add_message_to_heap(&mut self, recv_data: WriterMessagesData) {
        self.get_state_mut().heap.push(Reverse(recv_data));
    }

    pub(crate) fn finalize_sha256_builder(&mut self) -> Result<Sha256HashValue> {
        let sha256_builder = std::mem::replace(&mut self.sha256_builder, None);

        if let Some((context, expected)) = sha256_builder {
            let final_sha = Into::<Sha256HashValue>::into(context.finalize());

            if final_sha != expected {
                bail!(
                    "Content doesn't have expected SHA256 hash value!\nExpected: {}, final: {}",
                    hex::encode(expected),
                    hex::encode(final_sha)
                );
            }

            return Ok(final_sha);
        }

        bail!("SHA not enabled for writer");
    }

    /// Calls `finish` on the internal writer
    pub(crate) fn finish(self) -> io::Result<Vec<u8>> {
        self.writer.finish()
    }

    fn handle_final_message(&mut self, final_message: FinishMessage) -> Result<Sha256HashValue> {
        self.flush_inline(&final_message.data)?;

        let writer = std::mem::replace(&mut self.writer, Encoder::new(vec![], 0).unwrap());
        let finished = writer.finish()?;

        let sha = self.finalize_sha256_builder()?;

        self.get_state()
            .object_sender
            .send(EnsureObjectMessages::Data(SplitStreamWriterSenderData {
                external_data: finished,
                inline_content: vec![],
                seq_num: final_message.total_msgs,
                layer_num: final_message.layer_num,
            }))
            .with_context(|| format!("Failed to send object finalize message"))?;

        Ok(sha)
    }

    // Cannot `take` ownership of self, as we'll need it later
    //
    /// Returns whether we have finished writing all the data or not
    fn handle_received_data(&mut self, data: WriterMessages) -> Result<bool> {
        match data {
            WriterMessages::WriteData(recv_data) => {
                if let Some(final_sha) = self.get_state().final_sha {
                    // We've already received the final messae
                    let stream_path = format!("streams/{}", hex::encode(final_sha));

                    let object_path = Repository::format_object_path(&recv_data.digest);
                    self.repository.ensure_symlink(&stream_path, &object_path)?;

                    self.get_state()
                        .final_result_sender
                        .send(Ok((final_sha, recv_data.digest)))
                        .with_context(|| {
                            format!("Failed to send result for layer {final_sha:?}")
                        })?;

                    return Ok(true);
                }

                let seq_num = recv_data.object_data.seq_num;

                self.add_message_to_heap(recv_data);

                if seq_num != self.get_state().last {
                    return Ok(false);
                }

                self.write_message()?;
            }

            WriterMessages::Finish(final_msg) => {
                if self.get_state().final_message.is_some() {
                    panic!(
                        "Received two finalize messages for layer {}. Previous final message {:?}",
                        final_msg.layer_num,
                        self.get_state().final_message
                    );
                }

                // write all pending messages
                if !self.get_state().heap.is_empty() {
                    self.write_message()?;
                }

                let total_msgs = final_msg.total_msgs;

                if self.get_state().last >= total_msgs {
                    // We have received all the messages
                    // Finalize
                    let final_sha = self.handle_final_message(final_msg).unwrap();
                    self.get_state_mut().final_sha = Some(final_sha);
                } else {
                    // Haven't received all messages. Store the final message until we have
                    // received all
                    let state = self.get_state_mut();
                    state.final_message = Some(final_msg);
                }
            }
        }

        return Ok(false);
    }
}
