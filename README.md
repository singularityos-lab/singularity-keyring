# Singularity Keyring

A Secret Service daemon for the Singularity Desktop.

## Requirements

- [Meson](https://mesonbuild.com/) ≥ 0.59
- [Vala](https://vala.dev/) compiler
- GTK4
- GLib / GIO 2.0
- json-glib-1.0
- libgcrypt
- libsodium
- [libsingularity](https://github.com/singularityos-lab/libsingularity)

## Build & Install

```sh
meson setup build
meson compile -C build
meson install -C build
```

## License

GPL-3.0-only - see [LICENSE](LICENSE).
