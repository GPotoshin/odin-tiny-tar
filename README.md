`v.0.0.1`

Only files and directories are supported. THIS IMPLEMENTATION MAY NOT BE
SECURE. Contributions are appreciated.

Useful links:
> https://www.gnu.org/software/tar/manual/html_node/Standard.html
> https://pubs.opengroup.org/onlinepubs/9699919799/utilities/pax.html#tag_20_92_13

If you want a good quality library please use libtar or libarchive

## Use

Put file in your project in `<project_dir>/tar` directory and import it with
`import "tar"`.

Implementation exposes:

```
/*
    extract a tar archive contained in `data` into `dest_dir`.

    Parameters:
        data     – raw bytes of the tar archive
        dest_dir – destination directory (must already exist)
        flags    - opt-out feature flags; default {} keeps all checks enabled.
            Pass e.g. {.No_Checksum_Validation} to skip checksum verification.
*/
extract_all :: proc(data: []byte, dest_dir: string, flags: Feature_Flags = {}) -> Error

/*
    initiates a new reader

    Parameters:
        data     – raw bytes of the tar archive
*/
init_reader :: proc(data: []byte) -> (r: Reader)


/*
    checks offsets and advances Reader. should be called after init_reader or
    extract_entry. The end is .EOF

    Parameters:
        r        – contianer raw bytes, entry header and offset
        flags    - opt-out feature flags; default {} keeps all checks enabled.
            Pass e.g. {.No_Checksum_Validation} to skip checksum verification.
*/
next_entry :: proc(r: ^Reader, flags: Feature_Flags) -> Error


/*
    extract decompresses an entry in tar archive peinted by Reader into `dest_dir`.
    should be called after next entry on the very same Reader

    Parameters:
        r        – contianer raw bytes, entry header and offset
        dest_dir – destination directory (must already exist)
        flags    - opt-out feature flags; default {} keeps all checks enabled.
            Pass e.g. {.No_Checksum_Validation} to skip checksum verification.
*/
extract_entry :: proc(r: ^Reader, dest_dir: string, flags: Feature_Flags) -> Error
```

I.e. there are 2 interfaces `extract_all` or `init_reader`, `next_entry`, `extract_entry`.
You can look at the implementation of the former to get an idea how to use latter
