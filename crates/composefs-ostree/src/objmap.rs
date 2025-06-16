/* Implementation of the ObjectID Map format
 *
 * ObjectID maps are mappings from a foreign sha256 digest of some
 * form into an header of data, and an optional reference to an
 * external ObjectID (i.e. a fsverity) matching a composefs repo
 * ObjectID format.
 *
 * The file format is designed to be efficient to mmap, and when done so,
 * the additional data will be stored at 8-byte aligned offsets.
 *
 * Note: The object IDs referenced by an object map are not considered
 * referenced, in the sense of keeping them alive over a GC. So, users
 * have to either check for the existance of the references objects,
 * or ensure they stay alive via other means (such as splitstream
 * references).
 *
 * An object file has this format:
 *  (All ints are in little endian)
 *
 * header:
 * +-----------------------------------+
 * | u64: Magic number                 |
 * +-----------------------------------+
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
 * | u32: flags                        |
 * +-----------------------------------+
 *
 * flags:
 *   0x1 - If this is set, the data starts with an ObjectID referencing an external object
 *
 * Offset are 8byte aligned offsets from after the end of the
 * object_id_data array.
 *
 */
use anyhow::{Error, Result};
use memmap2::Mmap;
use std::fmt;
use std::fs::File;
use std::marker::PhantomData;
use std::mem::size_of;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use composefs::{fsverity::FsVerityHashValue, repository::Repository, util::Sha256Digest};

const OBJMAP_MAGIC_V1: u64 = 0xAFE138C18C463EF1;

#[derive(Debug)]
pub enum BackingData {
    Mapped(Mmap),
    Heap(Vec<u8>),
}

impl BackingData {
    fn as_bytes(&self) -> &[u8] {
        match self {
            BackingData::Mapped(m) => &m[..],
            BackingData::Heap(v) => &v[..],
        }
    }
}

#[derive(Debug, FromBytes, Immutable, IntoBytes, KnownLayout)]
#[repr(C)]
struct ObjMapHeader {
    magic: u64,
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

#[derive(Debug, FromBytes, Immutable, IntoBytes, KnownLayout)]
#[repr(C)]
struct DataRef {
    offset: u32,
    size: u32,
    flags: u32,
}

impl DataRef {
    pub fn get_offset(&self) -> usize {
        return u32::from_le(self.offset) as usize;
    }
    pub fn get_size(&self) -> usize {
        return u32::from_le(self.size) as usize;
    }
    pub fn get_flags(&self) -> u32 {
        return u32::from_le(self.flags);
    }
}

#[derive(Debug, FromBytes, Immutable, IntoBytes, KnownLayout)]
#[repr(C)]
struct DataRefs {
    datas: [DataRef],
}

#[derive(Debug)]
struct BuilderMapEntry<ObjectID: FsVerityHashValue> {
    mapped_id: Sha256Digest,
    verity: Option<ObjectID>,
    data: Vec<u8>,
}

impl<ObjectID: FsVerityHashValue> BuilderMapEntry<ObjectID> {
    pub fn get_flags(&self) -> u32 {
        let mut flags = 0u32;
        if self.verity.is_some() {
            flags |= 0x1;
        }
        flags
    }
    pub fn serialized_size(&self) -> u32 {
        return (self.data.len() +
            if self.verity.is_some() { size_of::<ObjectID>() } else { 0 }) as u32;
    }
    pub fn serialize(&self) -> Vec<u8> {
        if let Some(verity) = &self.verity {
            let mut v = Vec::new();
            v.extend_from_slice(verity.as_bytes());
            v.extend_from_slice(&self.data);
            v
        } else {
           self.data.clone()
        }
    }
}

#[derive(Debug)]
pub struct ObjectMapBuilder<ObjectID: FsVerityHashValue> {
    map: Vec<BuilderMapEntry<ObjectID>>,
}

fn align8(x: usize) -> usize {
    (x + 7) & !7
}

impl<ObjectID: FsVerityHashValue> ObjectMapBuilder<ObjectID> {
    pub fn new() -> Self {
        ObjectMapBuilder { map: vec![] }
    }

    pub fn iter(&self) -> impl Iterator<Item = (&Sha256Digest, Option<&ObjectID>, &[u8])> {
        self.map.iter().map(|e| (&e.mapped_id, e.verity.as_ref(), e.data.as_slice()))
    }

    pub fn contains(&self, mapped_id: &Sha256Digest) -> bool {
        match self.map.binary_search_by_key(mapped_id, |e| e.mapped_id) {
            Ok(_) => true,
            Err(..) => false,
        }
    }

    pub fn lookup(&self, mapped_id: &Sha256Digest) -> Option<(Option<&ObjectID>, &[u8])> {
        match self.map.binary_search_by_key(mapped_id, |e| e.mapped_id) {
            Ok(idx) => Some((self.map[idx].verity.as_ref(), &self.map[idx].data)),
            Err(..) => None,
        }
    }

    pub fn insert(&mut self, mapped_id: &Sha256Digest, verity: Option<&ObjectID>, data: Vec<u8>) {
        match self.map.binary_search_by_key(mapped_id, |e| e.mapped_id) {
            Ok(_idx) => {},
            Err(idx) => self.map.insert(
                idx,
                BuilderMapEntry {
                    mapped_id: *mapped_id,
                    verity: verity.cloned(),
                    data: data,
                },
            ),
        }
    }

    pub fn serialize(&self) -> Result<Vec<u8>> {
        /* Ensure we can index and count items using u32 */
        let item_count = self.map.len();
        if item_count > u32::MAX as usize {
            return Err(Error::msg("Too many items in object map"));
        }

        let mut header = ObjMapHeader {
            magic: u64::to_le(OBJMAP_MAGIC_V1),
            bucket_ends: [0; 256],
        };

        // Compute data offsets
        let mut data_size = 0usize;
        let mut data_offsets = vec![0usize; item_count];
        for (i, e) in self.map.iter().enumerate() {
            data_offsets[i] = data_size;
            data_size += align8(e.serialized_size() as usize);
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

        let size = size_of::<ObjMapHeader>()
            + item_count
                * (size_of::<Sha256Digest>() + size_of::<DataRef>())
            + data_size;

        let mut buf = Vec::with_capacity(size);

        // Add header
        buf.extend_from_slice(header.as_bytes());
        // Add mapped ids
        for e in self.map.iter() {
            buf.extend_from_slice(&e.mapped_id);
        }
        // Add data refs
        for (i, e) in self.map.iter().enumerate() {
            let d = DataRef {
                offset: u32::to_le(data_offsets[i] as u32),
                size: u32::to_le(e.serialized_size()),
                flags: u32::to_le(e.get_flags()),
            };
            buf.extend_from_slice(d.as_bytes());
        }
        // Add 8-aligned data chunks
        for e in self.map.iter() {
            let data = e.serialize();
            buf.extend_from_slice(&data);
            // Pad to 8
            let padding = align8(data.len()) - data.len();
            for _ in 0..padding {
                buf.push(0);
            }
        }

        Ok(buf)
    }
}

pub struct ObjectMapImage<ObjectID: FsVerityHashValue> {
    data: BackingData,
    bucket_ends: [u32; 256],
    item_count: usize,
    mapped_ids_offset: usize,
    data_refs_offset: usize,
    data_offset: usize,
    phantom: PhantomData<ObjectID>,
}

impl<ObjectID: FsVerityHashValue> fmt::Debug for ObjectMapImage<ObjectID> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mapped_ids = self.get_mapped_ids();
        let mut m = f.debug_map();
        for mapped_id in mapped_ids.iter() {
            m.entry(
                &hex::encode(mapped_id),
                &format!("{:?}", self.lookup(mapped_id).unwrap())
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

impl<ObjectID: FsVerityHashValue> ObjectMapImage<ObjectID> {
    #![allow(unsafe_code)] // Needed for the mmap

    pub fn load(repo: &Repository<ObjectID>, obj_id: &ObjectID) -> Result<Self> {
        let fd = repo.open_object(obj_id)?;

        let file = File::from(fd);
        let mmap = unsafe { Mmap::map(&file)? };

        ObjectMapImage::<ObjectID>::new(BackingData::Mapped(mmap))
    }

    pub fn new(data: BackingData) -> Result<Self> {
        let d = data.as_bytes();
        if d.len() < size_of::<ObjMapHeader>() {
            return Err(Error::msg("Not enough data"));
        }
        let mut pos = 0usize;
        let header_size = size_of::<ObjMapHeader>();
        let header_data = &d[pos..pos + header_size];
        pos += header_size;
        let h = ObjMapHeader::ref_from_bytes(header_data)
            .map_err(|_e| Error::msg(format!("Invalid objmap header")))?;

        // TODO: Add Algorithm to header magic

        if u64::from_le(h.magic) != OBJMAP_MAGIC_V1 {
            return Err(Error::msg(format!("Invalid objmap header magic")));
        }

        let mut buckets: [u32; 256] = h.bucket_ends;
        for b in buckets.iter_mut() {
            *b = u32::from_le(*b);
        }
        validate_buckets(&buckets)?;

        let item_count = buckets[255] as usize;

        let min_size = size_of::<ObjMapHeader>()
            + item_count
                * (size_of::<Sha256Digest>() + size_of::<DataRef>());

        if d.len() < min_size {
            return Err(Error::msg("Not enough data"));
        }

        let mapped_ids_offset = pos;
        let mapped_ids_size = item_count * size_of::<Sha256Digest>();
        let mapped_ids_data = &d[pos..pos + mapped_ids_size];
        pos += mapped_ids_size;

        let mapped_ids = Sha256DigestArray::ref_from_bytes(mapped_ids_data)
            .map_err(|_e| Error::msg(format!("Invalid objmap array")))?;

        if mapped_ids.ids.len() != item_count {
            return Err(Error::msg("Invalid objmap array"));
        }

        let data_refs_offset = pos;
        let data_refs_size = item_count * size_of::<DataRef>();
        let data_refs_data = &d[pos..pos + data_refs_size];
        pos += data_refs_size;

        let data_refs = DataRefs::ref_from_bytes(data_refs_data)
            .map_err(|_e| Error::msg(format!("Invalid objmap array")))?;

        if data_refs.datas.len() != item_count {
            return Err(Error::msg("Invalid objmap array"));
        }

        Ok(ObjectMapImage {
            data: data,
            bucket_ends: buckets,
            item_count: item_count,
            mapped_ids_offset: mapped_ids_offset,
            data_refs_offset: data_refs_offset,
            data_offset: pos,
            phantom: PhantomData,
        })
    }

    fn get_mapped_ids(&self) -> &[Sha256Digest] {
        let d = self.data.as_bytes();
        let mapped_ids_size = self.item_count * size_of::<Sha256Digest>();
        let mapped_ids_data = &d[self.mapped_ids_offset..self.mapped_ids_offset + mapped_ids_size];
        // We validated this in the constuctor, so unwrap is fine here
        &Sha256DigestArray::ref_from_bytes(mapped_ids_data)
            .unwrap()
            .ids
    }

    fn get_data_refs(&self) -> &[DataRef] {
        let d = self.data.as_bytes();
        let data_refs_size = self.item_count * size_of::<DataRef>();
        let data_refs_data = &d[self.data_refs_offset..self.data_refs_offset + data_refs_size];
        // We validated this in the constuctor, so unwrap is fine here
        &DataRefs::ref_from_bytes(data_refs_data).unwrap().datas
    }

    fn get_data(&self, data_ref: &DataRef) -> (Option<&ObjectID>, &[u8]) {
        let offset = data_ref.get_offset();
        let size = data_ref.get_size();
        let flags = data_ref.get_flags();

        let d = self.data.as_bytes();
        let start = self.data_offset + offset;
        let end = start + size;
        let data = &d[start..end];

        if flags & 0x1 != 0 {
            let (object_id, rest) = ObjectID::ref_from_prefix(data).unwrap();
            (Some(object_id), rest)
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
        let mapped_ids = self.get_mapped_ids();
        let in_bucket = &mapped_ids[start..end];
        match in_bucket.binary_search(mapped_id) {
            Ok(_) => true,
            Err(..) => false,
        }
    }

    pub fn lookup(&self, mapped_id: &Sha256Digest) -> Option<(Option<&ObjectID>, &[u8])> {
        let (start, end) = self.get_bucket(mapped_id);
        let mapped_ids = self.get_mapped_ids();
        let mapped_ids_in_bucket = &mapped_ids[start..end];
        let data_refs = self.get_data_refs();
        let data_refs_in_bucket = &data_refs[start..end];
        let index = match mapped_ids_in_bucket.binary_search(mapped_id) {
            Ok(i) => i,
            Err(..) => return None,
        };
        Some(self.get_data(&data_refs_in_bucket[index]))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use composefs::{fsverity::Sha256HashValue, util::parse_sha256};

    #[test]
    fn test_roundtrip() -> Result<()> {
        let mut builder = ObjectMapBuilder::<Sha256HashValue>::new();

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

        builder.insert(&mapped_1, Some(&objid_1), data_1.clone());
        builder.insert(&mapped_2, Some(&objid_2), data_2.clone());
        builder.insert(&mapped_3, Some(&objid_3), data_3.clone());

        let r1 = builder.lookup(&mapped_1);
        assert_eq!(r1, Some((Some(&objid_1), data_1.as_slice())));
        let r2 = builder.lookup(&mapped_2);
        assert_eq!(r2, Some((Some(&objid_2), data_2.as_slice())));
        let r3 = builder.lookup(&mapped_3);
        assert_eq!(r3, Some((Some(&objid_3), data_3.as_slice())));
        let r4 = builder.lookup(&mapped_4);
        assert_eq!(r4, None);

        let data = builder.serialize()?;

        let img = ObjectMapImage::<Sha256HashValue>::new(BackingData::Heap(data))?;

        let r1 = img.lookup(&mapped_1);
        assert_eq!(r1, Some((Some(&objid_1), data_1.as_slice())));
        let r2 = img.lookup(&mapped_2);
        assert_eq!(r2, Some((Some(&objid_2), data_2.as_slice())));
        let r3 = img.lookup(&mapped_3);
        assert_eq!(r3, Some((Some(&objid_3), data_3.as_slice())));
        let r4 = img.lookup(&mapped_4);
        assert_eq!(r4, None);

        Ok(())
    }
}
