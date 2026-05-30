project('singularity-keyring', ['vala', 'c'],
  version: '0.2.0',
  meson_version: '>= 0.59.0'
)

glib_dep     = dependency('glib-2.0')
gio_dep      = dependency('gio-2.0')
json_dep     = dependency('json-glib-1.0')
gtk_dep      = dependency('gtk4')

# libgcrypt + libsodium are pure C deps. Wrap them via find_library so
# valac does not try to load a Vala .vapi for them (which doesn't exist).
cc = meson.get_compiler('c')
gcrypt_lib   = cc.find_library('gcrypt', required: true)
sodium_lib   = cc.find_library('sodium', required: true)
gcrypt_dep   = declare_dependency(dependencies: [gcrypt_lib])
sodium_dep   = declare_dependency(dependencies: [sodium_lib])

sources = files(
  'src/main.vala',
  'src/service.vala',
  'src/collection.vala',
  'src/item.vala',
  'src/session.vala',
  'src/prompt.vala',
  'src/store.vala',
  'src/master.vala',
  'src/unlock_dialog.vala',
  'src/crypto.vapi',
  'src/crypto.c',
)

executable('singularity-keyring',
  sources,
  dependencies: [glib_dep, gio_dep, json_dep, gtk_dep, gcrypt_dep, sodium_dep],
  include_directories: include_directories('src'),
  vala_args: ['--pkg=gio-unix-2.0'],
  c_args: ['-DG_LOG_DOMAIN="sk-keyring"'],
  install: true,
  install_dir: get_option('bindir'),
)

install_data(
  'data/singularity-keyring.service',
  install_dir: get_option('datadir') / 'singularity' / 'systemd',
)
