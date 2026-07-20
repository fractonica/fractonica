use std::io::Cursor;

use fractonica_content::hash_bytes;

use super::*;

fn descriptor(bytes: &[u8]) -> ContentDescriptor {
    ContentDescriptor {
        content_id: hash_bytes(bytes),
        byte_length: bytes.len() as u64,
    }
}

#[test]
fn imports_verifies_and_reads_immutable_content() {
    let directory = tempfile::tempdir().unwrap();
    let store = ClientContentStore::open(directory.path()).unwrap();
    let bytes = b"fractonica media";
    let expected = descriptor(bytes);
    let blob = store.import(expected, Cursor::new(bytes)).unwrap();
    assert_eq!(blob.descriptor, expected);
    assert_eq!(store.read_range(expected, 3, 5).unwrap(), b"ctoni");
    assert_eq!(store.import(expected, Cursor::new(bytes)).unwrap(), blob);
    fs::write(&blob.path, b"xxxxxxxxxxxxxxxx").unwrap();
    assert!(matches!(
        store.blob(expected),
        Err(ClientContentError::DigestMismatch { .. })
    ));
}

#[test]
fn resumes_partial_download_and_publishes_only_after_digest_verification() {
    let directory = tempfile::tempdir().unwrap();
    let store = ClientContentStore::open(directory.path()).unwrap();
    let bytes = b"0123456789";
    let expected = descriptor(bytes);
    assert_eq!(
        store
            .append_download_chunk(expected, 0, &bytes[..4])
            .unwrap(),
        AppendResult {
            offset: 4,
            complete: false
        }
    );
    drop(store);

    let reopened = ClientContentStore::open(directory.path()).unwrap();
    assert_eq!(reopened.partial_offset(expected).unwrap(), 4);
    assert_eq!(
        reopened
            .append_download_chunk(expected, 4, &bytes[4..])
            .unwrap(),
        AppendResult {
            offset: 10,
            complete: true
        }
    );
    assert_eq!(reopened.read_range(expected, 0, 100).unwrap(), bytes);
}

#[test]
fn rejects_wrong_offsets_lengths_and_digests_without_publishing() {
    let directory = tempfile::tempdir().unwrap();
    let store = ClientContentStore::open(directory.path()).unwrap();
    let bytes = b"correct";
    let expected = descriptor(bytes);
    assert!(matches!(
        store.append_download_chunk(expected, 1, b"x"),
        Err(ClientContentError::OffsetMismatch {
            expected: 0,
            supplied: 1
        })
    ));
    assert!(matches!(
        store.import(expected, Cursor::new(b"too long!")),
        Err(ClientContentError::LengthOverflow { .. })
    ));
    assert!(matches!(
        store.append_download_chunk(expected, 0, b"xxxxxxx"),
        Err(ClientContentError::DigestMismatch { .. })
    ));
    assert_eq!(store.partial_offset(expected).unwrap(), 0);
    assert!(store.blob(expected).unwrap().is_none());
}

#[cfg(unix)]
#[test]
fn refuses_symlinked_partial_files() {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir().unwrap();
    let store = ClientContentStore::open(directory.path()).unwrap();
    let bytes = b"safe";
    let expected = descriptor(bytes);
    let wire = expected.content_id.to_string();
    let partial = directory
        .path()
        .join("partial")
        .join(format!("{}.part", &wire[8..]));
    let target = directory.path().join("target");
    fs::write(&target, b"do not touch").unwrap();
    symlink(&target, &partial).unwrap();
    assert!(matches!(
        store.append_download_chunk(expected, 0, bytes),
        Err(ClientContentError::UnsafePath(_))
    ));
    assert_eq!(fs::read(target).unwrap(), b"do not touch");
}
