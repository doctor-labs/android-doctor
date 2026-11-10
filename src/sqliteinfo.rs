//! SQLite database file header and schema inspection (issue #188).
//!
//! A small, bounds-checked reader for the SQLite file format header and the
//! `sqlite_master` table of a plain (non-WAL) database. It only reads: nothing
//! is executed and nothing inside the database is trusted. The header layout
//! follows the SQLite file format document (https://www.sqlite.org/fileformat2.html,
//! section 1.3): the first 100 bytes are the database header, and page 1 begins with an
//! 8-byte b-tree page header (section 1.6) followed by the cell pointer array.
//!
//! `scan` feeds the audit: a plaintext database is one with the `SQLite format 3` magic, so an
//! encrypted database (no readable magic) is never listed. `sqlite` prints one database.

use crate::term::sanitize;
use crate::tree::{Entry, Kind};
use anyhow::{Result, bail, ensure};
use serde_json::{Value, json};

/// The 16-byte magic string stored at the start of every SQLite database file.
pub const MAGIC: &[u8; 16] = b"SQLite format 3\0";

/// Text encoding stored in the header at offset 56 (4-byte big-endian integer).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextEncoding {
    Utf8,
    Utf16le,
    Utf16be,
    Utf16,
}

impl TextEncoding {
    fn from_u32(v: u32) -> Option<Self> {
        match v {
            1 => Some(TextEncoding::Utf8),
            2 => Some(TextEncoding::Utf16le),
            3 => Some(TextEncoding::Utf16be),
            4 => Some(TextEncoding::Utf16),
            _ => None,
        }
    }
}

/// A row of `sqlite_master`.
#[derive(Debug, Clone)]
pub struct TableInfo {
    pub name: String,
    pub kind: String, // "table" or "index"
    pub rootpage: u32,
    pub sql: Option<String>,
}

/// Parsed SQLite database header plus the schema table.
#[derive(Debug, Clone)]
pub struct DbInfo {
    /// Page size in bytes (offset 16). A header value of 1 means 65536.
    pub page_size: u32,
    /// File format write version (offset 18): 1=legacy, 2=wal.
    pub write_version: u8,
    /// File format read version (offset 19): 1=legacy, 2=wal.
    pub read_version: u8,
    /// Reserved-space size per page (offset 20).
    pub reserved: u16,
    /// Number of pages in the file (offset 28).
    pub page_count: u32,
    /// First freelist trunk page (offset 32; 0 means no freelist).
    pub freelist_trunk: u32,
    /// Number of freelist pages (offset 36).
    pub freelist_count: u32,
    /// Schema Cookie (offset 40).
    pub schema_cookie: u32,
    /// Text encoding (offset 56).
    pub text_encoding: Option<TextEncoding>,
    /// Tables and indexes from `sqlite_master`.
    pub tables: Vec<TableInfo>,
}

/// Largest header-only read we tolerate.
const MAX_HEADER_READ: u64 = 100;
/// Maximum number of sqlite_master rows we will parse (hostile-file guard).
const MAX_TABLES: usize = 10_000;

/// Decode a SQLite serial-type varint-encoded integer. Returns the value and the
/// number of bytes consumed. A varint is 1..9 bytes; each byte contributes 7 bits
/// and uses the high bit as a continuation flag.
fn read_varint(buf: &[u8], at: usize) -> Option<(u64, usize)> {
    let mut v: u64 = 0;
    let mut i = at;
    for _ in 0..9 {
        let b = *buf.get(i)? as u64;
        i += 1;
        v = (v << 7) | (b & 0x7f);
        if b & 0x80 == 0 {
            return Some((v, i));
        }
    }
    // 9-byte varint: the last byte contributes only 8 bits (not 7).
    let b = *buf.get(i - 1)? as u64;
    v = (v << 8) | b;
    Some((v, i))
}

/// Read a big-endian unsigned integer of 1, 2, 3, 4 or 8 bytes from `buf` at `off`,
/// returning `None` when out of bounds. Three-byte integers are big-endian.
fn read_be(buf: &[u8], off: usize, n: usize) -> Option<u64> {
    let end = off.checked_add(n)?;
    if end > buf.len() {
        return None;
    }
    let mut v: u64 = 0;
    for &b in &buf[off..end] {
        v = (v << 8) | (b as u64);
    }
    Some(v)
}

/// Return the on-disk byte length of a column value for the given serial type.
fn serial_type_len(serial_type: u64) -> Option<usize> {
    match serial_type {
        0 => Some(0),                                                       // NULL
        1 => Some(1),                                                       // 8-bit int
        2 => Some(2),                                                       // 16-bit int
        3 => Some(3),                                                       // 24-bit int
        4 => Some(4),                                                       // 32-bit int
        5 => Some(6),                                                       // 48-bit int
        6 => Some(8),                                                       // 64-bit int
        7 => Some(8),                                                       // float
        8 | 9 => Some(0),                                                   // constant 0 and 1
        n if n >= 12 && (n - 12) % 2 == 0 => Some(((n - 12) / 2) as usize), // blob
        n if n >= 13 && (n - 13) % 2 == 0 => Some(((n - 13) / 2) as usize), // text
        _ => None,
    }
}

/// Decode a text column of the given serial type starting at `start`.
fn text_from_serial(
    buf: &[u8],
    serial_type: u64,
    start: usize,
    encoding: Option<TextEncoding>,
) -> Option<String> {
    // Odd serial types >=13 are text; even >=12 are BLOB. (text is odd because the
    // "type" byte encodes odd for text, even for blob.)
    if serial_type < 13 || (serial_type - 13) % 2 == 1 {
        return None;
    }
    let len = ((serial_type - 13) / 2) as usize;
    let end = start.checked_add(len)?;
    if end > buf.len() {
        return None;
    }
    let bytes = &buf[start..end];
    match encoding {
        Some(TextEncoding::Utf16le) => decode_utf16(bytes, false),
        Some(TextEncoding::Utf16be) => decode_utf16(bytes, true),
        _ => str::from_utf8(bytes).ok().map(|s| s.to_string()),
    }
}

/// UTF-16 text of a database whose header says so (little or big endian units).
fn decode_utf16(bytes: &[u8], big_endian: bool) -> Option<String> {
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    let units = bytes.as_chunks::<2>().0.iter().map(|pair| {
        let pair = *pair;
        if big_endian {
            u16::from_be_bytes(pair)
        } else {
            u16::from_le_bytes(pair)
        }
    });
    char::decode_utf16(units)
        .collect::<Result<String, _>>()
        .ok()
}

/// Decode a record into its column values. Text columns are decoded as UTF-8
/// strings; integer columns (the sqlite_master `rootpage`) are decoded as `u64`.
fn decode_record(buf: &[u8], start: usize, encoding: Option<TextEncoding>) -> Option<Record> {
    let (hlen, mut i) = read_varint(buf, start)?;
    let header_end = start.checked_add(hlen as usize)?;
    if header_end > buf.len() {
        return None;
    }
    let mut serials: Vec<u64> = Vec::new();
    while i < header_end {
        let (st, n) = read_varint(buf, i)?;
        i = n;
        serials.push(st);
    }
    let mut body = header_end;
    let mut cols: Vec<Col> = Vec::with_capacity(serials.len());
    for st in &serials {
        let len = serial_type_len(*st)?;
        cols.push(col_from_serial(buf, *st, body, encoding)?);
        body = body.checked_add(len)?;
    }
    Some(Record { cols })
}

/// A decoded record column: text (from text/blob serial types) or an integer.
enum Col {
    Text(String),
    Int(u64),
    Null,
}

fn col_from_serial(
    buf: &[u8],
    serial_type: u64,
    start: usize,
    encoding: Option<TextEncoding>,
) -> Option<Col> {
    // Integer serial types 1..=6 are big-endian signed integers of 1,2,3,4,6,8 bytes.
    if (1..=6).contains(&serial_type) {
        let len = serial_type_len(serial_type)?;
        let end = start.checked_add(len)?;
        if end > buf.len() {
            return None;
        }
        let mut v: i64 = 0;
        for &b in &buf[start..end] {
            v = (v << 8) | b as i64;
        }
        // sign-extend from the high bit of the value's width.
        let bits = len * 8;
        if bits < 64 {
            let shift = 64 - bits;
            v = (v << shift) >> shift;
        }
        return Some(Col::Int(v as u64));
    }
    if let Some(s) = text_from_serial(buf, serial_type, start, encoding) {
        Some(Col::Text(s))
    } else {
        Some(Col::Null)
    }
}

struct Record {
    cols: Vec<Col>,
}

/// A b-tree page header (the first byte is the page type).
struct BtreeHeader {
    page_type: u8,
    cell_count: u16,
}

fn parse_btree_header(buf: &[u8], page_start: usize) -> Option<BtreeHeader> {
    let page_type = *buf.get(page_start)?;
    // Leaf table b-tree: 0x0d; interior: 0x05; index leaf: 0x0a; interior: 0x02.
    if !matches!(page_type, 0x02 | 0x05 | 0x0a | 0x0d) {
        return None;
    }
    if page_start + 8 > buf.len() {
        return None;
    }
    let cell_count = u16::from_be_bytes([buf[page_start + 3], buf[page_start + 4]]);
    Some(BtreeHeader {
        page_type,
        cell_count,
    })
}

/// Read the cell pointer array of page 1 and, for each leaf cell, decode the
/// `sqlite_master` row's record. Page 1 lives at offset 0; its b-tree header
/// sits at offset 100, followed by the 2-byte cell pointer array.
fn read_page1_tables(buf: &[u8], encoding: Option<TextEncoding>) -> Option<Vec<Record>> {
    let hdr_off = 100usize;
    let h = parse_btree_header(buf, hdr_off)?;
    if h.page_type != 0x0d {
        // sqlite_master must live on a leaf table-btree page.
        return None;
    }
    let cell_count = h.cell_count as usize;
    if cell_count > MAX_TABLES {
        return None;
    }
    let mut ptr = hdr_off + 8;
    let mut records = Vec::with_capacity(cell_count);
    for _ in 0..cell_count {
        let p0 = *buf.get(ptr)?;
        let p1 = *buf.get(ptr + 1)?;
        ptr += 2;
        let cell_off = usize::from(((p0 as u16) << 8) | (p1 as u16));
        if cell_off == 0 {
            return None;
        }
        // Leaf cell payload: varint(payload_length), varint(rowid), payload bytes.
        let (_plen, i) = read_varint(buf, cell_off)?;
        let (_rowid, i) = read_varint(buf, i)?;
        if let Some(rec) = decode_record(buf, i, encoding) {
            records.push(rec);
        }
    }
    Some(records)
}

/// Identify `buf` as a SQLite database and return its parsed header + schema.
/// Returns `Ok(None)` when the input is not a SQLite database (magic mismatch),
/// and an `Err` for a truncated or malformed header.
pub fn inspect(buf: &[u8]) -> anyhow::Result<Option<DbInfo>> {
    // The database header is the first 100 bytes; page 1's b-tree header follows.
    if buf.len() < MAX_HEADER_READ as usize {
        bail!(
            "file is too small to be a SQLite database ({} bytes)",
            buf.len()
        );
    }
    if &buf[..16] != MAGIC.as_slice() {
        // Not a SQLite database; the caller (e.g. `detect`) decides what to do.
        return Ok(None);
    }
    // page size: a header value of 1 means 65536.
    let page_size_raw = u16::from_be_bytes([buf[16], buf[17]]) as u32;
    let page_size = if page_size_raw == 1 {
        65536
    } else {
        page_size_raw
    };
    ensure!(page_size >= 512, "invalid page size {page_size}");
    let write_version = buf[18];
    let read_version = buf[19];
    let reserved = u16::from_be_bytes([buf[20], buf[21]]);
    let page_count = read_be(buf, 28, 4).unwrap_or(0) as u32;
    let freelist_trunk = read_be(buf, 32, 4).unwrap_or(0) as u32;
    let freelist_count = read_be(buf, 36, 4).unwrap_or(0) as u32;
    let schema_cookie = read_be(buf, 40, 4).unwrap_or(0) as u32;
    let encoding_raw = read_be(buf, 56, 4).unwrap_or(0) as u32;
    let text_encoding = TextEncoding::from_u32(encoding_raw);

    // WAL journals (write_version/read_version == 2) store the live schema on a wal
    // page, not on page 1; we only inspect plain (rollback-mode) databases here.
    let tables = if write_version == 1 && read_version == 1 {
        read_page1_tables(buf, text_encoding)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|rec| {
                // sqlite_master columns: type, name, tbl_name, rootpage, sql.
                let [kind, name, _tbl, rootpage, sql] = rec.cols.as_slice() else {
                    return None;
                };
                let kind = match kind {
                    Col::Text(s) => s.as_str(),
                    _ => return None,
                };
                let name = match name {
                    Col::Text(s) => s.as_str(),
                    _ => return None,
                };
                let rootpage: u32 = match rootpage {
                    Col::Int(v) => *v as u32,
                    _ => 0,
                };
                let sql = match sql {
                    Col::Text(s) => Some(s.clone()),
                    _ => None,
                };
                if kind.is_empty() || name.is_empty() {
                    return None;
                }
                Some(TableInfo {
                    kind: kind.to_string(),
                    name: name.to_string(),
                    rootpage,
                    sql,
                })
            })
            .collect()
    } else {
        Vec::new()
    };

    Ok(Some(DbInfo {
        page_size,
        write_version,
        read_version,
        reserved,
        page_count,
        freelist_trunk,
        freelist_count,
        schema_cookie,
        text_encoding,
        tables,
    }))
}

/// Bytes read from the start of a file for `sqlite`: the header and page 1 of any page size up to
/// the 65536 maximum. The schema lives on page 1 here (overflow pages are not followed).
pub const HEAD_BYTES: u64 = 65536;
/// Largest database the audit reads whole.
const MAX_DB_BYTES: u64 = 64 * 1024 * 1024;
/// Most databases the audit reads per image.
const MAX_DBS: usize = 64;

/// A plaintext database found by the audit: its in-image path, its mode and its header/schema.
#[derive(Debug, Clone)]
pub struct DbFile {
    pub path: String,
    pub mode: u32,
    pub info: DbInfo,
}

/// The plaintext databases of one image. An encrypted database has no readable magic and is
/// not listed.
#[derive(Debug, Clone, Default)]
pub struct SqliteAudit {
    pub dbs: Vec<DbFile>,
}

/// Under an app's `databases/` directory, Android's place for app data.
pub fn is_app_db(path: &str) -> bool {
    path.split('/').any(|c| c == "databases")
}

/// Named like a database, or an app database. Only these are read, so an image is not scanned
/// byte for byte.
fn is_candidate(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    [".db", ".sqlite", ".sqlite3"]
        .iter()
        .any(|ext| lower.ends_with(ext))
        || is_app_db(path)
}

/// Every plaintext database among the candidates of an image. `read` gets an in-image path.
pub fn scan(entries: &[Entry], read: &mut dyn FnMut(&str) -> Result<Vec<u8>>) -> SqliteAudit {
    let mut out = SqliteAudit::default();
    for e in entries {
        if out.dbs.len() >= MAX_DBS {
            break;
        }
        if e.kind != Kind::File || e.size > MAX_DB_BYTES || !is_candidate(&e.path) {
            continue;
        }
        let Ok(bytes) = read(&e.path) else { continue };
        if let Ok(Some(info)) = inspect(&bytes) {
            out.dbs.push(DbFile {
                path: e.path.clone(),
                mode: e.mode,
                info,
            });
        }
    }
    out
}

/// The text encoding's name as the header stores it.
pub fn encoding_name(e: Option<TextEncoding>) -> &'static str {
    match e {
        Some(TextEncoding::Utf8) => "UTF-8",
        Some(TextEncoding::Utf16le) => "UTF-16le",
        Some(TextEncoding::Utf16be) => "UTF-16be",
        Some(TextEncoding::Utf16) => "UTF-16",
        None => "unknown",
    }
}

/// JSON of one database: header fields and the schema rows (`audit` and `sqlite --json`).
pub fn info_json(info: &DbInfo) -> Value {
    json!({
        "page_size": info.page_size,
        "page_count": info.page_count,
        "freelist_count": info.freelist_count,
        "freelist_trunk_page": info.freelist_trunk,
        "schema_cookie": info.schema_cookie,
        "reserved_bytes": info.reserved,
        "text_encoding": encoding_name(info.text_encoding),
        "wal": info.write_version == 2 || info.read_version == 2,
        "schema": info.tables.iter().map(|t| json!({
            "type": t.kind, "name": t.name, "rootpage": t.rootpage, "sql": t.sql,
        })).collect::<Vec<_>>(),
    })
}

/// Text report of one database for `sqlite`. Names and SQL come from the file, so they are
/// sanitized before printing.
pub fn describe(path: &str, info: &DbInfo) -> String {
    let mut out = vec![
        format!("{}: SQLite database", sanitize(path)),
        format!(
            "  page size {}, {} pages, {} freelist pages, text encoding {}",
            info.page_size,
            info.page_count,
            info.freelist_count,
            encoding_name(info.text_encoding)
        ),
        format!(
            "  schema cookie {}, reserved bytes per page {}",
            info.schema_cookie, info.reserved
        ),
    ];
    if info.write_version == 2 || info.read_version == 2 {
        out.push("  WAL journal: the schema is not read (plain databases only)".to_string());
    }
    out.push(format!("  schema ({} objects):", info.tables.len()));
    for t in &info.tables {
        let sql = t.sql.as_deref().map_or("-".to_string(), sanitize);
        out.push(format!(
            "    {} {} (rootpage {}): {}",
            t.kind,
            sanitize(&t.name),
            t.rootpage,
            sql
        ));
    }
    out.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Oracle: python3's `sqlite3` module (its own SQLite build, not this parser) reads the same
    /// bytes read-only and prints the header fields and schema rows as JSON.
    fn python_oracle(bytes: &[u8], tag: &str) -> Value {
        let dir =
            std::env::temp_dir().join(format!("ad-sqlite-oracle-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("db");
        std::fs::write(&p, bytes).unwrap();
        let script = "import json, sqlite3, sys\n\
            c = sqlite3.connect('file:' + sys.argv[1] + '?mode=ro', uri=True)\n\
            q = lambda s: c.execute(s).fetchone()[0]\n\
            print(json.dumps({'page_size': q('PRAGMA page_size'), 'page_count': q('PRAGMA page_count'),\n\
            'freelist_count': q('PRAGMA freelist_count'), 'encoding': q('PRAGMA encoding'),\n\
            'schema': [list(r) for r in c.execute('SELECT type, name, rootpage, sql FROM sqlite_master ORDER BY rowid')]}))\n";
        let out = std::process::Command::new("python3")
            .arg("-I")
            .arg("-c")
            .arg(script)
            .arg(&p)
            .output()
            .expect("python3 is required for the sqlite3 oracle");
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice(&out.stdout).unwrap()
    }

    /// Ground-truth fixture built with the system `sqlite3`:
    ///   sqlite3 sample.db "create table users(id integer primary key, name text);
    ///   create table orders(total real); create index idx_orders on orders(total);"
    /// `sqlite3 --version`: 3.50.6. Verified fields:
    ///   - magic: "SQLite format 3\\0"
    ///   - page_size: 4096  (`PRAGMA page_size`)
    ///   - page_count: 5     (`PRAGMA page_count`)
    ///   - schema_cookie: 3  (on-disk value at header offset 40, verified with xxd; the
    ///     in-memory `PRAGMA schema_cookie` differs and is not written to the file verbatim)
    ///   - text_encoding: 1 = UTF-8  (`PRAGMA encoding`)
    ///   - sqlite_master rows in rowid (cell-pointer) order:
    ///
    ///     users      | table  | rootpage 3
    ///     orders     | table  | rootpage 4
    ///     idx_orders | index  | rootpage 5
    const SAMPLE: &[u8] = include_bytes!("../tests/fixtures/sqlite/sample.db");

    #[test]
    fn reads_the_database_header_fields() {
        let info = inspect(SAMPLE).unwrap().unwrap();
        assert_eq!(info.page_size, 4096);
        assert_eq!(info.write_version, 1);
        assert_eq!(info.read_version, 1);
        assert_eq!(info.reserved, 64);
        assert_eq!(info.page_count, 5);
        assert_eq!(info.freelist_trunk, 0);
        assert_eq!(info.freelist_count, 0);
        assert_eq!(info.schema_cookie, 3);
        assert_eq!(info.text_encoding, Some(TextEncoding::Utf8));
    }

    #[test]
    fn page_size_of_one_means_65536() {
        let mut db = SAMPLE.to_vec();
        // offset 16..18 holds the 2-byte big-endian page size; 1 => 65536.
        db[16] = 0;
        db[17] = 1;
        let info = inspect(&db).unwrap().unwrap();
        assert_eq!(info.page_size, 65536);
    }

    #[test]
    fn reads_the_schema_tables_and_indexes() {
        let info = inspect(SAMPLE).unwrap().unwrap();
        let names: Vec<String> = info.tables.iter().map(|t| t.name.clone()).collect();
        assert_eq!(names, ["users", "orders", "idx_orders"]);
        let kinds: Vec<String> = info.tables.iter().map(|t| t.kind.clone()).collect();
        assert_eq!(kinds, ["table", "table", "index"]);
        let users = info.tables.iter().find(|t| t.name == "users").unwrap();
        assert_eq!(users.rootpage, 3);
        assert_eq!(
            users.sql.as_deref(),
            Some("CREATE TABLE users(id integer primary key, name text)")
        );
    }

    #[test]
    fn non_sqlite_input_is_not_a_database() {
        // A plain f2fs/ext4 header is not "SQLite format 3"; inspect returns Ok(None).
        let mut bad = SAMPLE.to_vec();
        bad[0] = 0;
        bad[1] = 0;
        assert!(inspect(&bad).unwrap().is_none());
        assert!(inspect(b"").is_err());
    }

    #[test]
    fn a_utf16le_database_reports_its_encoding() {
        // A real UTF-16le database, built with: sqlite3 u16.db "PRAGMA encoding='UTF-16le';
        // create table s(x);"
        let bytes = make_utf16_db();
        let info = inspect(&bytes).unwrap().unwrap();
        assert_eq!(info.text_encoding, Some(TextEncoding::Utf16le));
    }

    #[test]
    fn hostile_truncations_never_panic() {
        // Every prefix of the header must not panic; a short file bails, a non-SQLite
        // prefix returns None.
        for cut in (0..SAMPLE.len()).step_by(13) {
            let _ = inspect(&SAMPLE[..cut]);
        }
    }

    #[test]
    fn header_and_schema_agree_with_python_sqlite3() {
        // Header fields: https://www.sqlite.org/fileformat2.html section 1.3; page 1 b-tree
        // layout: section 1.6. The oracle reads the same bytes independently.
        for (bytes, tag) in [(SAMPLE.to_vec(), "sample"), (make_utf16_db(), "utf16")] {
            let want = python_oracle(&bytes, tag);
            let info = inspect(&bytes).unwrap().unwrap();
            assert_eq!(info.page_size as u64, want["page_size"], "{tag}");
            assert_eq!(info.page_count as u64, want["page_count"], "{tag}");
            assert_eq!(info.freelist_count as u64, want["freelist_count"], "{tag}");
            assert_eq!(encoding_name(info.text_encoding), want["encoding"], "{tag}");
            let got: Vec<Value> = info
                .tables
                .iter()
                .map(|t| json!([t.kind, t.name, t.rootpage, t.sql]))
                .collect();
            assert_eq!(Value::Array(got), want["schema"], "{tag}");
        }
    }

    fn make_utf16_db() -> Vec<u8> {
        let dir = std::env::temp_dir().join(format!("ad-sqlite-u16-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("u16.db");
        let st = std::process::Command::new("sqlite3")
            .arg(&p)
            .arg("PRAGMA encoding='UTF-16le'; create table s(x);")
            .status();
        if !st.map(|s| s.success()).unwrap_or(false) {
            panic!("sqlite3 not available to build a UTF-16 fixture");
        }
        let bytes = std::fs::read(&p).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        bytes
    }
}
