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
fn imports_native_file_from_derived_descriptor_and_deduplicates() {
    let directory = tempfile::tempdir().unwrap();
    let store = ClientContentStore::open(directory.path().join("store")).unwrap();
    let first_source = directory.path().join("first.bin");
    let second_source = directory.path().join("second.bin");
    let bytes = b"native attachment bytes";
    fs::write(&first_source, bytes).unwrap();
    fs::write(&second_source, bytes).unwrap();

    let first = store.import_file(&first_source).unwrap();
    let second = store.import_file(&second_source).unwrap();

    assert_eq!(first, second);
    assert_eq!(first.descriptor, descriptor(bytes));
    assert_eq!(store.read_range(first.descriptor, 0, 100).unwrap(), bytes);
    assert_eq!(fs::read(first_source).unwrap(), bytes);
    assert_eq!(
        fs::read_dir(store.root().join("partial")).unwrap().count(),
        0
    );
}

#[test]
fn rejects_non_regular_native_sources() {
    let directory = tempfile::tempdir().unwrap();
    let store = ClientContentStore::open(directory.path().join("store")).unwrap();

    assert!(matches!(
        store.import_file(directory.path()),
        Err(ClientContentError::UnsafePath(_))
    ));
}

#[cfg(unix)]
#[test]
fn rejects_symlinked_native_sources() {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir().unwrap();
    let store = ClientContentStore::open(directory.path().join("store")).unwrap();
    let target = directory.path().join("target.bin");
    let source = directory.path().join("source.bin");
    fs::write(&target, b"do not import through a link").unwrap();
    symlink(&target, &source).unwrap();

    assert!(matches!(
        store.import_file(source),
        Err(ClientContentError::UnsafePath(_))
    ));
    assert_eq!(
        fs::read_dir(store.root().join("partial")).unwrap().count(),
        0
    );
}

#[test]
fn rejects_lengths_above_the_protocol_bound() {
    assert!(matches!(
        ensure_protocol_length(MAX_CONTENT_BYTE_LENGTH + 1),
        Err(ClientContentError::ContentTooLarge {
            actual,
            maximum: MAX_CONTENT_BYTE_LENGTH
        }) if actual == MAX_CONTENT_BYTE_LENGTH + 1
    ));
}

// Creating a sparse file beyond the protocol maximum is a useful integration
// check on filesystems that support it. Windows may reserve the full logical
// length and fail with StorageFull before the importer can inspect metadata;
// the platform-independent boundary check above still covers the guard.
#[cfg(not(windows))]
#[test]
fn rejects_native_sources_above_the_protocol_bound_without_copying() {
    let directory = tempfile::tempdir().unwrap();
    let store = ClientContentStore::open(directory.path().join("store")).unwrap();
    let source = directory.path().join("oversize.bin");
    let file = File::create(&source).unwrap();
    file.set_len(MAX_CONTENT_BYTE_LENGTH + 1).unwrap();
    drop(file);

    assert!(matches!(
        store.import_file(source),
        Err(ClientContentError::ContentTooLarge {
            actual,
            maximum: MAX_CONTENT_BYTE_LENGTH
        }) if actual == MAX_CONTENT_BYTE_LENGTH + 1
    ));
    assert_eq!(
        fs::read_dir(store.root().join("partial")).unwrap().count(),
        0
    );
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
