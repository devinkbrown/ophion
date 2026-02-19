openssl_dep = dependency('openssl', required: true)

discordd_exe = executable('discordd',
  'discordd.c',
  dependencies: [openssl_dep],
  install: true,
  install_rpath: get_option('libdir'))
