/* Implementation of the ObjectID Map format
 *
 * ObjectID maps are mappings from a foreign sha256 digest of some
 * form into an header of data, and an optional reference to an
 * external ObjectID (i.e. a fsverity) matching a composefs repo
 * ObjectID format.
 *
 * The file format is intended to be inside of a splitstream and
 * uses the splitstream header to reference the external object ids.
 *
 * An object file has this format:
 *  (All ints are in little endian)
 *
 * buckets;
 *  256 x (indexes are into mapped_ids)
 * +-----------------------------------+
 * | u32: end index of bucket          |
 * +-----------------------------------+
 *
 * mapped_ids:
 *  n_objects x (sorted)
 * +-----------------------------------+
 * |  [u8; 32] mapped object id        |
 * +-----------------------------------+
 *
 * object_data:
 *  n_objects x (same order as  object_ids)
 * +-----------------------------------+
 * | u32: offset to per-object data    |
 * | u32: length of per-object data    |
 * | u32: Index of external object ref |
 * |      or MAXUINT32 if none.        |
 * +-----------------------------------+
 *
 * Offset are 8byte aligned offsets from after the end of the
 * object_data array.
 *
 */
use anyhow::{Error, Result};
use gvariant::aligned_bytes::{AlignedBuf, AlignedSlice, TryAsAligned, A8};
use std::{fmt, fs::File, io::Read, mem::size_of, sync::Arc};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use composefs::{
    fsverity::FsVerityHashValue,
    repository::Repository,
    splitstream::{SplitStreamReader, SplitStreamWriter},
    util::Sha256Digest,
};

const OBJMAP_CONTENT_TYPE: u64 = 0xAFE138C18C463EF1;

#[derive(Debug, FromBytes, Immutable, IntoBytes, KnownLayout)]
#[repr(C)]
struct ObjMapHeader {
    bucket_ends: [u32; 256],
}

#[derive(Debug, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
struct Sha256DigestArray {
    ids: [Sha256Digest],
}

#[derive(Debug, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
struct ObjectIDArray<ObjectID: FsVerityHashValue> {
    ids: [ObjectID],
}

const NO_EXTERNAL_INDEX: u32 = u32::MAX;

#[derive(Debug, FromBytes, Immutable, IntoBytes, KnownLayout, Clone)]
#[repr(C)]
struct DataRef {
    offset: u32,
    size: u32,
    external_index: u32,
}

impl DataRef {
    pub fn new(offset: usize, size: usize, external_index: Option<usize>) -> Self {
        DataRef {
            offset: u32::to_le(offset as u32),
            size: u32::to_le(size as u32),
            external_index: u32::to_le(match external_index {
                Some(idx) => idx as u32,
                None => NO_EXTERNAL_INDEX,
            }),
        }
    }
    pub fn get_offset(&self) -> usize {
        return u32::from_le(self.offset) as usize;
    }
    pub fn get_size(&self) -> usize {
        return u32::from_le(self.size) as usize;
    }
    pub fn get_external_index(&self) -> Option<usize> {
        match u32::from_le(self.external_index) {
            NO_EXTERNAL_INDEX => None,
            idx => Some(idx as usize),
        }
    }
}

#[derive(Debug, FromBytes, Immutable, IntoBytes, KnownLayout)]
#[repr(C)]
struct DataRefs {
    datas: [DataRef],
}

#[derive(Debug)]
struct WriterMapEntry<ObjectID: FsVerityHashValue> {
    mapped_id: Sha256Digest,
    verity: Option<ObjectID>,
    data: AlignedBuf,
}

#[derive(Debug)]
pub struct ObjectMapWriter<ObjectID: FsVerityHashValue> {
    map: Vec<WriterMapEntry<ObjectID>>,
}

fn align8(x: usize) -> usize {
    (x + 7) & !7
}

impl<ObjectID: FsVerityHashValue> ObjectMapWriter<ObjectID> {
    pub fn new() -> Self {
        ObjectMapWriter { map: vec![] }
    }

    pub fn iter(
        &self,
    ) -> impl Iterator<Item = (&Sha256Digest, Option<&ObjectID>, &AlignedSlice<A8>)> {
        self.map
            .iter()
            .map(|e| (&e.mapped_id, e.verity.as_ref(), &e.data[..]))
    }

    pub fn contains(&self, mapped_id: &Sha256Digest) -> bool {
        match self.map.binary_search_by_key(mapped_id, |e| e.mapped_id) {
            Ok(_) => true,
            Err(..) => false,
        }
    }

    pub fn lookup(
        &self,
        mapped_id: &Sha256Digest,
    ) -> Option<(Option<&ObjectID>, &AlignedSlice<A8>)> {
        match self.map.binary_search_by_key(mapped_id, |e| e.mapped_id) {
            Ok(idx) => Some((self.map[idx].verity.as_ref(), &self.map[idx].data)),
            Err(..) => None,
        }
    }

    pub fn insert(&mut self, mapped_id: &Sha256Digest, verity: Option<&ObjectID>, data: &[u8]) {
        match self.map.binary_search_by_key(mapped_id, |e| e.mapped_id) {
            Ok(_idx) => {}
            Err(idx) => {
                let mut aligned_data = AlignedBuf::new();
                aligned_data.with_vec(|v| v.extend_from_slice(data));
                self.map.insert(
                    idx,
                    WriterMapEntry {
                        mapped_id: *mapped_id,
                        verity: verity.cloned(),
                        data: aligned_data,
                    },
                );
            }
        }
    }

    pub fn merge_from(&mut self, reader: &ObjectMapReader<ObjectID>) {
        for (sha256, objid, data) in reader.iter() {
            self.insert(sha256, objid, data);
        }
    }

    pub fn serialize(&self, repo: &Arc<Repository<ObjectID>>) -> Result<(ObjectID, Sha256Digest)> {
        let mut ss = SplitStreamWriter::<ObjectID>::new(repo, OBJMAP_CONTENT_TYPE, true, None);

        /* Ensure we can index and count items using u32 (leaving one for NO_EXTERNAL_INDEX) */
        let item_count = self.map.len();
        if item_count > (NO_EXTERNAL_INDEX - 1) as usize {
            return Err(Error::msg("Too many items in object map"));
        }

        let mut header = ObjMapHeader {
            bucket_ends: [0; 256],
        };

        // Compute data offsets and add external object references
        let mut data_size = 0usize;
        let mut data_offsets = vec![0usize; item_count];
        for (i, e) in self.map.iter().enumerate() {
            data_offsets[i] = data_size;
            data_size += align8(e.data.len());

            if let Some(verity) = &e.verity {
                ss.add_external_reference(&verity)
            }
        }

        // Ensure all data can be indexed by u32
        if data_size > u32::MAX as usize {
            return Err(Error::msg("Too large data in object map"));
        }

        // Compute bucket ends
        for e in self.map.iter() {
            // Initially end is just the count
            header.bucket_ends[e.mapped_id[0] as usize] += 1;
        }
        for i in 1..256 {
            // Then we sum them up to the end
            header.bucket_ends[i] += header.bucket_ends[i - 1];
        }
        // Convert buckets to little endian
        for i in 0..256 {
            header.bucket_ends[i] = u32::to_le(header.bucket_ends[i]);
        }

        // Add header
        ss.write_inline(header.as_bytes());
        // Add mapped ids
        for e in self.map.iter() {
            ss.write_inline(&e.mapped_id);
        }
        // Add data refs
        for (i, e) in self.map.iter().enumerate() {
            let idx = if let Some(verity) = &e.verity {
                ss.lookup_external_reference(&verity)
            } else {
                None
            };
            let d = DataRef::new(data_offsets[i], e.data.len(), idx);
            ss.write_inline(d.as_bytes());
        }

        // Add 8-aligned data chunks
        for e in self.map.iter() {
            ss.write_inline(&e.data);
            // Pad to 8
            let padding = align8(e.data.len()) - e.data.len();
            if padding > 0 {
                ss.write_inline(&vec![0u8; padding]);
            }
        }

        let (objid, sha256) = ss.done()?;

        // This is safe because we passed true to compute this above
        Ok((objid, sha256.unwrap()))
    }
}

pub struct ObjectMapReader<ObjectID: FsVerityHashValue> {
    data: AlignedBuf,
    bucket_ends: [u32; 256],
    mapped_ids: Vec<Sha256Digest>,
    datas: Vec<DataRef>,
    pub refs: Vec<ObjectID>,
}

impl<ObjectID: FsVerityHashValue> fmt::Debug for ObjectMapReader<ObjectID> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut m = f.debug_map();
        for mapped_id in self.mapped_ids.iter() {
            m.entry(
                &hex::encode(mapped_id),
                &format!("{:?}", self.lookup(mapped_id).unwrap()),
            );
        }
        m.finish()
    }
}

fn validate_buckets(buckets: &[u32; 256]) -> Result<()> {
    for i in 1..256 {
        // Bucket ends are (non-strictly) increasing
        if buckets[i] < buckets[i - 1] {
            return Err(Error::msg(format!("Invalid objmap bucket data")));
        }
    }
    Ok(())
}

impl<ObjectID: FsVerityHashValue> ObjectMapReader<ObjectID> {
    pub fn load(repo: &Repository<ObjectID>, obj_id: &ObjectID) -> Result<Self> {
        let fd = repo.open_object(obj_id)?;

        let file = File::from(fd);
        let mut ss = SplitStreamReader::new(file, Some(OBJMAP_CONTENT_TYPE))?;

        let mut buf = AlignedBuf::new();

        buf.with_vec(|v| v.resize(size_of::<ObjMapHeader>(), 0u8));
        let n_read = ss.read(&mut buf)?;
        if n_read != buf.len() {
            return Err(Error::msg("Not enough data"));
        }

        let h = ObjMapHeader::ref_from_bytes(&buf)
            .map_err(|_e| Error::msg(format!("Invalid objmap header")))?;

        let mut buckets: [u32; 256] = h.bucket_ends;
        for b in buckets.iter_mut() {
            *b = u32::from_le(*b);
        }
        validate_buckets(&buckets)?;
        let item_count = buckets[255] as usize;

        buf.with_vec(|v| v.resize(item_count * size_of::<Sha256Digest>(), 0u8));
        let n_read = ss.read(&mut buf)?;
        if n_read != buf.len() {
            return Err(Error::msg("Not enough data"));
        };
        let mapped_ids = Sha256DigestArray::ref_from_bytes(&buf)
            .map_err(|_e| Error::msg(format!("Invalid objmap array")))?;

        if mapped_ids.ids.len() != item_count {
            return Err(Error::msg("Invalid objmap array"));
        }
        let mapped = mapped_ids.ids.to_vec();

        buf.with_vec(|v| v.resize(item_count * size_of::<DataRef>(), 0u8));
        let n_read = ss.read(&mut buf)?;
        if n_read != buf.len() {
            return Err(Error::msg("Not enough data"));
        };

        let data_refs = DataRefs::ref_from_bytes(&buf)
            .map_err(|_e| Error::msg(format!("Invalid objmap array")))?;

        if data_refs.datas.len() != item_count {
            return Err(Error::msg("Invalid objmap array"));
        }

        let datas = data_refs.datas.to_vec();

        buf.with_vec(|v| {
            v.resize(0, 0u8);
            ss.read_to_end(v)
        })?;

        Ok(ObjectMapReader {
            data: buf,
            bucket_ends: buckets,
            mapped_ids: mapped,
            datas: datas,
            refs: ss.refs.clone(),
        })
    }

    fn get_data(&self, data_ref: &DataRef) -> (Option<&ObjectID>, &AlignedSlice<A8>) {
        let start = data_ref.get_offset();
        let end = start + data_ref.get_size();
        // The unwrap here is safe, because data is always 8 aligned
        let data = &self.data[start..end].try_as_aligned().unwrap();

        if let Some(index) = data_ref.get_external_index() {
            (Some(&self.refs[index]), data)
        } else {
            (None, data)
        }
    }

    fn get_bucket(&self, mapped_id: &Sha256Digest) -> (usize, usize) {
        let first = mapped_id[0] as usize;
        let start = if first == 0 {
            0
        } else {
            self.bucket_ends[first - 1]
        };
        let end = self.bucket_ends[first];
        (start as usize, end as usize)
    }

    pub fn contains(&self, mapped_id: &Sha256Digest) -> bool {
        let (start, end) = self.get_bucket(mapped_id);
        let in_bucket = &self.mapped_ids[start..end];
        match in_bucket.binary_search(mapped_id) {
            Ok(_) => true,
            Err(..) => false,
        }
    }

    pub fn lookup(
        &self,
        mapped_id: &Sha256Digest,
    ) -> Option<(Option<&ObjectID>, &AlignedSlice<A8>)> {
        let (start, end) = self.get_bucket(mapped_id);
        let mapped_ids_in_bucket = &self.mapped_ids[start..end];
        let data_refs_in_bucket = &self.datas[start..end];
        let index = match mapped_ids_in_bucket.binary_search(mapped_id) {
            Ok(i) => i,
            Err(..) => return None,
        };
        Some(self.get_data(&data_refs_in_bucket[index]))
    }

    pub fn iter(
        &self,
    ) -> impl Iterator<Item = (&Sha256Digest, Option<&ObjectID>, &AlignedSlice<A8>)> {
        self.mapped_ids.iter().enumerate().map(|e| {
            let (objid, data) = self.get_data(&self.datas[e.0]);
            (e.1, objid, data)
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use composefs::{fsverity::Sha256HashValue, util::parse_sha256};

    #[test]
    fn test_roundtrip() -> Result<()> {
        let mut writer = ObjectMapWriter::<Sha256HashValue>::new();

        let mapped_1 =
            parse_sha256("84682bb6f0404ba9b81d5f3b753be2a08f1165389229ee8516acbd5700182cad")?;
        let mapped_2 =
            parse_sha256("4b37fb400b28a686343ba83f00789608e0b624b13bf50d713bc8a9b0de514e00")?;
        let mapped_3 =
            parse_sha256("4b37fb400b28a686343ba83f00789608e0b624b13bf50d713bc8a9b0de514e01")?;
        let mapped_4 =
            parse_sha256("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")?;
        let objid_1 = Sha256HashValue::from_hex(
            "0a11b9bb6258495dbe1677b2dc4e0d6c4cc86aef8b7c274756d40a878a921a8a",
        )?;
        let objid_2 = Sha256HashValue::from_hex(
            "a0729185616450a10bd8439549221433edc7154d9f87a454768a368de2e5967a",
        )?;
        let objid_3 = Sha256HashValue::from_hex(
            "37d2eeabfa179742b9b490cc3072cc289124e74f5aa3d4bc270862f07890c1cc",
        )?;
        let data_1 = vec![42u8];
        let data_2 = vec![12u8, 17u8];
        let data_3 = vec![];

        writer.insert(&mapped_1, Some(&objid_1), &data_1);
        writer.insert(&mapped_2, Some(&objid_2), &data_2);
        writer.insert(&mapped_3, Some(&objid_3), &data_3);

        let r1 = writer.lookup(&mapped_1);
        assert_eq!(r1, Some((Some(&objid_1), data_1.as_slice())));
        let r2 = writer.lookup(&mapped_2);
        assert_eq!(r2, Some((Some(&objid_2), data_2.as_slice())));
        let r3 = writer.lookup(&mapped_3);
        assert_eq!(r3, Some((Some(&objid_3), data_3.as_slice())));
        let r4 = writer.lookup(&mapped_4);
        assert_eq!(r4, None);

        Ok(())
    }
}
