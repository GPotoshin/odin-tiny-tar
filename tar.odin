package tar

/*
    Only files and directories are supported. THIS IMPLEMENTATION MAY NOT BE
    SECURE. Contributions are appreciated.

    useful links:
    > https://www.gnu.org/software/tar/manual/html_node/Standard.html
    > https://pubs.opengroup.org/onlinepubs/9699919799/utilities/pax.html#tag_20_92_13
*/

import "core:os"
import "core:fmt"
import "core:strings"
import "core:path/filepath"

Error :: enum {
    None,
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

Tar_Header :: struct #packed {
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

#assert(size_of(Tar_Header) == TAR_BLOCK_SIZE)

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
verify_checksum :: proc(raw: []u8, header: ^Tar_Header) -> Error {
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

/*
    extract a tar archive contained in `data` into `dest_dir`.

    Parameters:
        data     – raw bytes of the tar archive
        dest_dir – destination directory (must already exist)
        flags    - opt-out feature flags; default {} keeps all checks enabled.
            Pass e.g. {.No_Checksum_Validation} to skip checksum verification.
*/
extract :: proc(data: []byte, dest_dir: string, flags: Feature_Flags = {}) -> Error {
    arena: virtual.Arena
    if arena_err := virtual.arena_init_growing(&arena); arena_err != nil {
        return .No_Memory 
    }
    defer virtual.arena_destroy(&arena)
    arena_alloc := virtual.arena_allocator(&arena)

    offset := 0

    for {
        if offset + TAR_BLOCK_SIZE > len(data) {
            return .Unexpected_EOF
        }
        raw_header := data[offset : offset + TAR_BLOCK_SIZE]
        header     := (^Tar_Header)(raw_data(raw_header))
        offset     += TAR_BLOCK_SIZE

        // 2 consecutive zero blocks signal end-of-archive
        if header.name[0] == 0 {
            all_zero := true
            for b in raw_header {
                if b != 0 {
                    all_zero = false
                    break
                }
            }
            if !all_zero do return .Invalid_Header

            if offset + TAR_BLOCK_SIZE > len(data) do return .Unexpected_EOF
            for b in data[offset : offset + TAR_BLOCK_SIZE] {
                if b != 0 do return .Invalid_Header
            }
            return .None
        }

        if .No_Checksum_Validation not_in flags {
            if ck_err := verify_checksum(raw_header, header); ck_err != .None {
                return ck_err
            }
        }

        name   := cstr_from_fixed(header.name[:])
        prefix := cstr_from_fixed(header.prefix[:])

        size, size_err := octal_to_int(header.size[:])
        if size_err != .None do return size_err

        typeflag := Type_Flag(header.typeflag)

        full_name := name
        if len(prefix) > 0 {
            full_name = strings.join({prefix, name}, "/", arena_alloc)
        }
        if path_err := validate_path(full_name, flags); path_err != .None {
            return path_err
        }
        dest_path := filepath.join({dest_dir, full_name}, arena_alloc)
        clean_dest := filepath.clean(dest_dir,  arena_alloc)
        clean_path := filepath.clean(dest_path, arena_alloc)
        if !strings.has_prefix(clean_path, clean_dest + "/") && clean_path != clean_dest {
            return .Path_Outside_Root
        }

        #partial switch typeflag {
        case .Normal, .Normal_Alt:
            if offset + size > len(data) {
                return .Unexpected_EOF
            }
            parent := filepath.dir(dest_path, arena_alloc)
            if mk_err := os.make_directory(parent, 0o755); mk_err != nil {
                _ = mk_err
            }
            f, ferr := os.open(dest_path, os.O_WRONLY | os.O_CREATE | os.O_TRUNC, 0o644)
            if ferr != nil {
                fmt.eprintfln("tar: cannot open %q: %v", dest_path, ferr)
            } else {
                written, werr := os.write(f, data[offset : offset + size])
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
        next   := offset + blocks * TAR_BLOCK_SIZE
        if next < offset || next > len(data) {
            return .Unexpected_EOF
        }
        offset = next
    }
    return .None
}
