//! Cold reset at the flash boundary (no NvStore, variable arena or retained
//! journal survives). Exercise the MM writer, not the boot-time EDK2 writer.
#[path = "../src/mm/nvstore.rs"]
mod nvstore;

mod flash {
    use std::cell::RefCell;
    pub const ERASE_BLOCK: u64 = 4096;
    #[derive(Clone, Copy, Debug)]
    pub enum Cut {
        Before,
        Half,
        FirstBlock,
        Complete,
    }

    #[derive(Default)]
    pub struct Media {
        pub bytes: Vec<u8>,
        pub ops: Vec<(usize, bool)>,
        pub cut: Option<(usize, Cut)>,
    }
    thread_local! {pub static MEDIA: RefCell<Media> = RefCell::default();}
    #[derive(Clone, Copy)]
    pub struct Flash;
    impl Flash {
        pub const fn empty() -> Self {
            Self
        }
        pub fn read(&self, offset: u64, dst: &mut [u8]) -> bool {
            MEDIA.with_borrow(|m| dst.copy_from_slice(&m.bytes[offset as usize..][..dst.len()]));
            true
        }
        fn mutate(
            &self,
            offset: u64,
            len: usize,
            erase: bool,
            byte: impl Fn(usize, u8) -> u8,
        ) -> bool {
            MEDIA.with_borrow_mut(|m| {
                let index = m.ops.len();
                m.ops.push((offset as usize, erase));
                let tear = m.cut.filter(|&(n, _)| n == index);
                let n = match tear.map(|(_, cut)| cut) {
                    Some(Cut::Before) => 0,
                    Some(Cut::Half) => len / 2,
                    Some(Cut::FirstBlock) => len.min(ERASE_BLOCK as usize),
                    Some(Cut::Complete) | None => len,
                };
                for (i, b) in m.bytes[offset as usize..][..n].iter_mut().enumerate() {
                    *b = byte(i, *b);
                }
                tear.is_none()
            })
        }
        pub fn program(&self, offset: u64, data: &[u8]) -> bool {
            self.mutate(offset, data.len(), false, |i, b| b & data[i])
        }
        pub fn program_bits(&self, offset: u64, bits: u8) -> bool {
            self.program(offset, &[bits])
        }
        pub fn erase(&self, offset: u64, len: u64) -> bool {
            assert!(offset.is_multiple_of(ERASE_BLOCK) && len.is_multiple_of(ERASE_BLOCK));
            self.mutate(offset, len as usize, true, |_, _| 0xff)
        }
    }
}
use crabefi_runtime_abi::{VariableTimestamp, mm::MIN_STORE_SIZE};
use flash::{Cut, Flash, MEDIA, Media};
use nvstore::{Error, NvStore};

fn open() -> NvStore {
    let mut store = NvStore::empty();
    store.open(Flash, 0, MIN_STORE_SIZE as u32).unwrap();
    store
}

#[test]
fn interrupted_compaction_recovers_committed_records_without_retained_ram() {
    const GUID: [u8; 16] = [3; 16];
    const NAME: &[u16] = &[78, 0];
    let time = VariableTimestamp {
        year: 2026,
        ..Default::default()
    };
    MEDIA.with_borrow_mut(|m| m.bytes = vec![0xff; MIN_STORE_SIZE as usize]);
    let mut store = open();
    store
        .write(&GUID, NAME, 7, &vec![1; 32 * 1024], None)
        .unwrap();
    store.write(&GUID, NAME, 7, &[2; 600], Some(time)).unwrap();
    let seed = MEDIA.with_borrow(|m| m.bytes.clone());
    let append = |s: &mut NvStore| s.write(&GUID, &[79, 0], 7, &[3; 8192], None);
    MEDIA.with_borrow_mut(|m| m.ops.clear());
    append(&mut store).unwrap();
    // Include every mutation through final spare erase, but not the new
    // record append: it has a different commit protocol.
    let spare = (MIN_STORE_SIZE / 2) as usize;
    let last = MEDIA.with_borrow(|m| {
        assert_eq!(m.ops[0], (spare, true));
        assert!(m.ops.contains(&(0, true)));
        m.ops.iter().rposition(|op| *op == (spare, true)).unwrap()
    });
    for cut in 0..=last {
        for torn in [Cut::Before, Cut::Half, Cut::FirstBlock, Cut::Complete] {
            MEDIA.with_borrow_mut(|m| {
                *m = Media {
                    bytes: seed.clone(),
                    ..Media::default()
                }
            });
            let mut running = open();
            MEDIA.with_borrow_mut(|m| {
                m.ops.clear();
                m.cut = Some((cut, torn));
            });
            assert_eq!(append(&mut running), Err(Error::Device), "cut {cut}");
            MEDIA.with_borrow_mut(|m| m.cut = None);
            let mut recovered = open();
            let mut seen = 0;
            recovered
                .for_each_live(&mut [0; 16], &mut [0; 8192], &mut |r, name, data| {
                    assert_eq!(
                        (r.guid, name, r.attributes, r.timestamp),
                        (GUID, NAME, 7, time)
                    );
                    assert_eq!(data, &[2; 600]);
                    seen += 1;
                    Ok(())
                })
                .unwrap();
            assert_eq!(seen, 1, "cut {cut}, torn {torn:?}");
            append(&mut recovered).unwrap();
            let mut names = Vec::new();
            open()
                .for_each_live(&mut [0; 16], &mut [0; 8192], &mut |r, name, data| {
                    assert_eq!((r.guid, r.attributes), (GUID, 7));
                    match name {
                        [78, 0] => {
                            assert_eq!(data, &[2; 600]);
                            assert_eq!(r.timestamp, time);
                        }
                        [79, 0] => assert_eq!(data, &[3; 8192]),
                        _ => panic!("unexpected recovered record"),
                    }
                    names.push(name[0]);
                    Ok(())
                })
                .unwrap();
            names.sort_unstable();
            assert_eq!(names, [78, 79]);
        }
    }
}
