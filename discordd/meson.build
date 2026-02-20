discordd_exe = executable('discordd',
  'discordd.c',
  dependencies: [wolfssl_dep],
  install: true,
  install_rpath: get_option('libdir'))

# Unit tests for the pure codec functions in discordd.
# The test includes discordd.c directly with DISCORD_NO_MAIN defined so that
# only the self-contained helper functions (pct_encode, json_str, etc.)
# are compiled; the TLS/socket code is never called.
test_discord_codec = executable('test_discord_codec',
  'tests/test_codec.c',
  c_args: ['-DDISCORD_NO_MAIN'],
  dependencies: [wolfssl_dep],
  include_directories: [])

test('discord_codec', test_discord_codec)
