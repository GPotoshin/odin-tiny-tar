`v.0.0.0`

Only files and directories are supported. THIS IMPLEMENTATION MAY NOT BE
SECURE. Contributions are appreciated.

Useful links:
> https://www.gnu.org/software/tar/manual/html_node/Standard.html
> https://pubs.opengroup.org/onlinepubs/9699919799/utilities/pax.html#tag_20_92_13

If you want a good quality library please use libtar or libarchive

## Use

Put file in your project in `<project_dir>/tar` directory and import it with
`import "tar"`. Implementation exposes a single function:

```
/*
    extract a tar archive contained in `data` into `dest_dir`.

    Parameters:
        data     – raw bytes of the tar archive
        dest_dir – destination directory (must already exist)
        flags    - opt-out feature flags; default {} keeps all checks enabled.
            Pass e.g. {.No_Checksum_Validation} to skip checksum verification.
*/
extract :: proc(data: []byte, dest_dir: string, flags: Feature_Flags = {}) -> Error
```
