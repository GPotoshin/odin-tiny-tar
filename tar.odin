package tar

/*
    Only files and directories are supported. THIS IMPLEMENTATION MAY NOT BE
    SECURE. Contributions are apreciated.

    useful links:
    > https://www.gnu.org/software/tar/manual/html_node/Standard.html
    > https://pubs.opengroup.org/onlinepubs/9699919799/utilities/pax.html#tag_20_92_13
*/

import "core:os"
import "core:fmt"
import "core:strings"
import "core:path/filepath"
import "core:mem/virtual"

Error :: enum {
    None,
    EOF,
    Unexpected_EOF,
    Short_Read,
    Invalid_Header,
    Invalid_Checksum,
    Numeric_Value_Too_Big,
    Path_Outside_Root,
    Unsafe_Path,
    Unsupported_Header,
    No_Memory,
}

Type_Flag :: enum u8 {
    Normal        = '0',
    Normal_Alt    = 0,
    Hard_Link     = '1',
    Sym_Link      = '2',
    Char_Spec     = '3',
    Block_Spec    = '4',
    Directory     = '5',
    Fifo          = '6',
    Contiguous    = '7',
    Pax_Global    = 'g',
    Pax_Extended  = 'x',
    Gnu_Long_Name = 'L',
    Gnu_Long_Link = 'K',
    Gnu_Sparse    = 'S',
}

TAR_BLOCK_SIZE :: 512

Header :: struct #packed {
    name:     [100]u8,
    mode:     [8]u8,
    uid:      [8]u8,
    gid:      [8]u8,
    size:     [12]u8,
    mtime:    [12]u8,
    checksum: [8]u8,
    typeflag: u8,
    linkname: [100]u8,
    magic:    [6]u8,
    version:  [2]u8,
    uname:    [32]u8,
    gname:    [32]u8,
    devmajor: [8]u8,
    devminor: [8]u8,
    prefix:   [155]u8,
    _pad:     [12]u8,
}

#assert(size_of(Header) == TAR_BLOCK_SIZE)

/*
    Feature flags

    Security checks are ON by default. Pass the relevant flags to selectively loosen validation for trusted inputs
    or exotic archive generators that violate strict conventions.

    Default (no flags):
        - Checksum is validated
        - Absolute paths are rejected

    Example — trust the archive, skip checksum verification:
        extract(data, "/tmp/out", flags = {.No_Checksum_Validation})
*/
Feature_Flag :: enum u32 {
    No_Checksum_Validation, // skip header checksum verification
    No_Abs_Path_Check,      // allow absolute paths (e.g. /etc/passwd) in entries
}
Feature_Flags :: bit_set[Feature_Flag; u32]

FEATURES_STRICT   :: Feature_Flags{}

@(private)
octal_to_int :: proc(b: []u8) -> (result: int, err: Error) {
    MAX :: max(int)
    for c in b {
        if c == 0 || c == ' ' do break
        if c < '0' || c > '7' do return 0, .Invalid_Header
        digit := int(c - '0')
        if result > (MAX - digit) / 8 do return 0, .Numeric_Value_Too_Big
        result = result * 8 + digit
    }
    return result, .None
}

@(private)
cstr_from_fixed :: proc(b: []u8) -> string {
    for i := 0; i < len(b); i += 1 {
        if b[i] == 0 do return string(b[:i])
    }
    return string(b)
}

/*
    Compute the unsigned sum checksum of a tar header block.
    The 8-byte checksum field is treated as all spaces (0x20) during computation,
    per the POSIX spec.
*/
@(private)
compute_checksum :: proc(raw: []u8) -> u32 {
    sum: u32 = 0
    // checksum field is at byte offset 148, length 8
    CKSUM_OFF :: 148
    CKSUM_LEN :: 8
    for i := 0; i < TAR_BLOCK_SIZE; i += 1 {
        if i >= CKSUM_OFF && i < CKSUM_OFF + CKSUM_LEN {
            sum += 0x20 // treat as space
        } else {
            sum += u32(raw[i])
        }
    }
    return sum
}

// Validate the stored checksum in the header against the raw block bytes.
@(private)
verify_checksum :: proc(raw: []u8, header: ^Header) -> Error {
    stored, err := octal_to_int(header.checksum[:])
    if err != .None do return .Invalid_Checksum
    computed := compute_checksum(raw)
    if u32(stored) != computed do return .Invalid_Checksum
    return .None
}

/*
    Reject paths that escape the destination root:
      - absolute paths
      - any component that is ".."
      - null bytes (defense-in-depth against OS quirks)
*/
@(private)
validate_path :: proc(p: string, flags: Feature_Flags) -> Error {
    if len(p) == 0                  do return .Unsafe_Path
    if strings.contains_rune(p, 0)  do return .Unsafe_Path
    if .No_Abs_Path_Check not_in flags {
        if filepath.is_abs(p) do return .Unsafe_Path
    }
    rest := p
    for {
        dir, file := filepath.split(rest)
        if file == ".." do return .Path_Outside_Root
        if dir == "" || dir == rest do break
        rest = strings.trim_right(dir, "/\\")
    }
    return .None
}

Reader :: struct {
    data: []byte,
    header: ^Header,
    offset: int,
}

/*
    initiates a new reader

    Parameters:
        data     – raw bytes of the tar archive
*/
init_reader :: proc(data: []byte) -> (r: Reader) {
    r.data = data
    return
}

/*
    checks offsets and advances Reader. should be called after init_reader or
    extract_entry. The end is .EOF

    Parameters:
        r        – contianer raw bytes, entry header and offset
        flags    - opt-out feature flags; default {} keeps all checks enabled.
            Pass e.g. {.No_Checksum_Validation} to skip checksum verification.
*/
next_entry :: proc(r: ^Reader, flags: Feature_Flags) -> Error {
    if r.offset + TAR_BLOCK_SIZE > len(r.data) {
        return .Unexpected_EOF
    }
    raw_header := r.data[r.offset : r.offset + TAR_BLOCK_SIZE]
    r.header    = (^Header)(raw_data(raw_header))
    r.offset   += TAR_BLOCK_SIZE
    // 2 consecutive zero blocks signal end-of-archive
    if r.header.name[0] == 0 {
        all_zero := true
        for b in raw_header {
            if b != 0 {
                all_zero = false
                break
            }
        }
        if !all_zero do return .Invalid_Header

        if r.offset + TAR_BLOCK_SIZE > len(r.data) do return .Unexpected_EOF
        for b in r.data[r.offset : r.offset + TAR_BLOCK_SIZE] {
            if b != 0 do return .Invalid_Header
        }
        return .EOF
    }

    if .No_Checksum_Validation not_in flags {
        if ck_err := verify_checksum(raw_header, r.header); ck_err != .None {
            return ck_err
        }
    }
    return .None
}

/*
    extract decompresses an entry in tar archive peinted by Reader into `dest_dir`.
    should be called after next entry on the very same Reader

    Parameters:
        r        – contianer raw bytes, entry header and offset
        dest_dir – destination directory (must already exist)
        flags    - opt-out feature flags; default {} keeps all checks enabled.
            Pass e.g. {.No_Checksum_Validation} to skip checksum verification.
*/
extract_entry :: proc(r: ^Reader, dest_dir: string, flags: Feature_Flags) -> Error {
    name   := cstr_from_fixed(r.header.name[:])
    prefix := cstr_from_fixed(r.header.prefix[:])

    size, size_err := octal_to_int(r.header.size[:])
    if size_err != .None do return size_err

    typeflag := Type_Flag(r.header.typeflag)

    full_name := name
    if len(prefix) > 0 {
        full_name = strings.join({prefix, name}, "/", context.temp_allocator)
    }
    if path_err := validate_path(full_name, flags); path_err != .None {
        return path_err
    }
    dest_path := filepath.join({dest_dir, full_name}, context.temp_allocator)
    clean_dest := filepath.clean(dest_dir,  context.temp_allocator)
    clean_path := filepath.clean(dest_path, context.temp_allocator)
    clean_dest_prefix := strings.concatenate({clean_dest, "/"}, context.temp_allocator)
    if !strings.has_prefix(clean_path, clean_dest_prefix) && clean_path != clean_dest {
        return .Path_Outside_Root
    }

    #partial switch typeflag {
    case .Normal, .Normal_Alt:
        if r.offset + size > len(r.data) {
            return .Unexpected_EOF
        }
        parent := filepath.dir(dest_path, context.temp_allocator)
        if mk_err := os.make_directory(parent, 0o755); mk_err != nil {
            _ = mk_err
        }
        f, ferr := os.open(dest_path, os.O_WRONLY | os.O_CREATE | os.O_TRUNC, 0o644)
        if ferr != nil {
            fmt.eprintfln("tar: cannot open %q: %v", dest_path, ferr)
        } else {
            written, werr := os.write(f, r.data[r.offset : r.offset + size])
            os.close(f)
            if werr != nil || written != size {
                return .Short_Read
            }
        }

    case .Directory:
        if mk_err := os.make_directory(dest_path, 0o755); mk_err != nil {
            _ = mk_err
        }

    case:
        return .Unsupported_Header
    }

    blocks := (size + TAR_BLOCK_SIZE - 1) / TAR_BLOCK_SIZE
    next   := r.offset + blocks * TAR_BLOCK_SIZE
    if next < r.offset || next > len(r.data) {
        return .Unexpected_EOF
    }
    r.offset = next
    return .None
}

/*
    extract decompresses a tar archive contained in `data` into `dest_dir`.

    Parameters:
        data     – raw bytes of the tar archive
        dest_dir – destination directory (must already exist)
        flags    - opt-out feature flags; default {} keeps all checks enabled.
            Pass e.g. {.No_Checksum_Validation} to skip checksum verification.
*/
extract_all :: proc(data: []byte, dest_dir: string, flags: Feature_Flags = {}) -> Error {
    arena: virtual.Arena
    if arena_err := virtual.arena_init_growing(&arena); arena_err != nil {
        return .No_Memory 
    }
    defer virtual.arena_destroy(&arena)
    context.temp_allocator = virtual.arena_allocator(&arena)

    r := init_reader(data)

    for {
        err := next_entry(&r, flags)
        if err == .EOF do return .None
        if err != nil do return err
        extract_entry(&r, dest_dir, flags) or_return
    }
    return .None
}
