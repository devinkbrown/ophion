project('ophion', 'c',
  version : '0.8',
  license : 'GPL-2.0-or-later',
  meson_version : '>=0.53')

cc = meson.get_compiler('c')

# configuration_data must be declared before any cdata.set() calls below.
cdata = configuration_data()

# libdl
libdl_lib = cc.find_library('dl', has_headers: ['dlfcn.h'], required: false)
if libdl_lib.found()
  libdl_deps = [libdl_lib]
else
  libdl_deps = []
endif
libdl_dep = declare_dependency(dependencies: libdl_deps)

# liburing (io_uring backend)
liburing_dep = dependency('liburing', required: false)
if liburing_dep.found()
  cdata.set('HAVE_LIBURING', true)
endif

# librt
librt_lib = cc.find_library('rt', has_headers: ['signal.h', 'time.h'], required: false)
if librt_lib.found()
  librt_deps = [librt_lib]
else
  librt_deps = []
endif
librt_dep = declare_dependency(dependencies: librt_deps)

# flex / bison
flex = find_program('flex', required: true)
bison = find_program('bison', required: true)

flex_gen = generator(flex,
  output: '@PLAINNAME@.y.c',
  arguments: ['-o', '@OUTPUT@', '@INPUT@'])

bison_gen = generator(bison,
  output: ['@BASENAME@.c', '@BASENAME@.h'],
  arguments: ['@INPUT@', '--defines=@OUTPUT1@', '--output=@OUTPUT0@'])

# TLS: wolfSSL (OpenSSL-compatible) is preferred, then mbedtls, then gnutls.
# wolfSSL provides both the crypto (libcrypto equivalent) and TLS layers.
wolfssl_dep = dependency('wolfssl', required: false)
if wolfssl_dep.found()
  cdata.set('HAVE_LIBCRYPTO', true)
  # Make wolfSSL's OpenSSL compatibility headers visible as <openssl/...>
  add_project_arguments('-I/usr/include/wolfssl', language: 'c')
  # Force-include wolfssl/options.h so OPENSSL_EXTRA and related macros are
  # defined before any wolfSSL or wolfSSL-OpenSSL-compat header is seen.
  add_project_arguments('-include', 'wolfssl/options.h', language: 'c')
endif

# grr, mbedtls has no pc file so we have to do this ourselves.  gross.
mbedtls_lib = cc.find_library('mbedtls', has_headers: ['mbedtls/ssl.h'], required: false)
mbedcrypto_lib = cc.find_library('mbedcrypto', required: false)
mbedx509_lib = cc.find_library('mbedx509', required: false)

if not wolfssl_dep.found() and mbedtls_lib.found() and mbedcrypto_lib.found() and mbedx509_lib.found()
  mbedtls_dep = declare_dependency(include_directories: '/usr/include',
    dependencies: [mbedtls_lib, mbedcrypto_lib, mbedx509_lib])

  cdata.set('HAVE_MBEDTLS', true)
else
  mbedtls_dep = disabler()
endif

if not wolfssl_dep.found() and not mbedtls_dep.found()
  gnutls_dep = dependency('gnutls', required: false)

  if gnutls_dep.found()
    cdata.set('HAVE_GNUTLS', true)
  endif
else
  gnutls_dep = disabler()
endif

if wolfssl_dep.found()
  # wolfSSL is our OpenSSL replacement; use its compat layer.
  libssl_dep = wolfssl_dep
  cdata.set('HAVE_OPENSSL', true)
elif not mbedtls_dep.found() and not gnutls_dep.found()
  libssl_dep = disabler()
else
  libssl_dep = disabler()
endif

# sqlite3 — required by ircd (services DB) and bandb.
sqlite3_dep = dependency('sqlite3', required: true)

# hyperscan — optional; enables the compiled-pattern filter extension.
hyperscan_dep = dependency('hyperscan', required: false)
if hyperscan_dep.found()
  cdata.set('HAVE_HYPERSCAN', true)
endif

# branding
cdata.set_quoted('BRANDING_NAME', meson.project_name())
cdata.set_quoted('BRANDING_VERSION', meson.project_version())

# nicklen / topiclen / whowas size
max_nicklen = get_option('nicklen')
max_topiclen = get_option('topiclen')
max_nickname_history_length = get_option('whowas-history-length')

cdata.set('NICKLEN', max_nicklen)
cdata.set('TOPICLEN', max_topiclen)
cdata.set('NICKNAMEHISTORYLENGTH', max_nickname_history_length)

# heap sizes
small_heap_size = 256
medium_heap_size = 1024
large_heap_size = 4096
huge_heap_size = 8192
jumbo_heap_size = 32768

small_heaps = ['PCLIENT_HEAP_SIZE', 'ND_HEAP_SIZE', 'CONFITEM_HEAP_SIZE', 'AWAY_HEAP_SIZE']
medium_heaps = ['LCLIENT_HEAP_SIZE', 'MONITOR_HEAP_SIZE', 'FD_HEAP_SIZE']
large_heaps = ['BAN_HEAP_SIZE', 'TOPIC_HEAP_SIZE', 'LINEBUF_HEAP_SIZE']
huge_heaps = ['CHANNEL_HEAP_SIZE', 'CLIENT_HEAP_SIZE', 'USER_HEAP_SIZE', 'DNODE_HEAP_SIZE']
jumbo_heaps = ['MEMBER_HEAP_SIZE']

heaps = [
  [small_heaps, small_heap_size],
  [medium_heaps, medium_heap_size],
  [large_heaps, large_heap_size],
  [huge_heaps, huge_heap_size],
  [jumbo_heaps, jumbo_heap_size]
]

foreach heap : heaps
  foreach heap_item : heap.get(0)
    cdata.set(heap_item, heap.get(1))
  endforeach
endforeach

# functions
check_functions = [
  ['HAVE_SNPRINTF', 'snprintf', 'stdio.h'],
  ['HAVE_VSNPRINTF', 'vsnprintf', 'stdio.h'],
  ['HAVE_SOCKETPAIR', 'socketpair', 'sys/socket.h'],
  ['HAVE_GETTIMEOFDAY', 'gettimeofday', 'sys/time.h'],
  ['HAVE_WRITEV', 'writev', 'sys/uio.h'],
  ['HAVE_SENDMSG', 'sendmsg', 'sys/socket.h'],
  ['HAVE_GMTIME_R', 'gmtime_r', 'time.h'],
  ['HAVE_STRTOK_R', 'strtok_r', 'string.h'],
  ['HAVE_USLEEP', 'usleep', 'unistd.h'],
  ['HAVE_POSIX_SPAWN', 'posix_spawn', 'spawn.h'],
  ['HAVE_GETEXECNAME', 'getexecname', 'stdlib.h'],
  ['HAVE_STRLCAT', 'strlcat', 'string.h'],
  ['HAVE_STRLCPY', 'strlcpy', 'string.h'],
  ['HAVE_STRNDUP', 'strndup', 'string.h'],
  ['HAVE_STRNLEN', 'strnlen', 'string.h'],
  ['HAVE_STRCASESTR', 'strcasestr', 'string.h'],
  ['HAVE_STRCASECMP', 'strcasecmp', 'string.h'],
  ['HAVE_STRNCASECMP', 'strncasecmp', 'string.h'],
  ['HAVE_FSTAT', 'fstat', 'sys/stat.h'],
  ['HAVE_SIGNALFD', 'signalfd', 'sys/signalfd.h'],
  ['HAVE_SELECT', 'select', 'sys/select.h'],
  ['HAVE_POLL', 'poll', 'poll.h'],
  ['HAVE_KEVENT', 'kevent', 'sys/event.h'],
  ['HAVE_PORT_CREATE', 'port_create', 'port.h'],
  ['HAVE_EPOLL_CTL', 'epoll_ctl', 'sys/epoll.h'],
  ['HAVE_ARC4RANDOM', 'arc4random', 'stdlib.h'],
  ['HAVE_GETRUSAGE', 'getrusage', 'sys/resource.h'],
  ['HAVE_TIMERFD_CREATE', 'timerfd_create', 'sys/timerfd.h'],
]

foreach f : check_functions
  if cc.has_function(f.get(1), prefix : '#include <' + f.get(2) + '>') and cc.has_header_symbol(f.get(2), f.get(1))
    cdata.set(f.get(0), 1)
  endif
endforeach

# paths
prefix = get_option('prefix')
cdata.set_quoted('PREFIX', prefix)
cdata.set_quoted('IRCD_PREFIX', prefix)

libexec_dir = prefix / 'bin'
cdata.set_quoted('PKGLIBEXECDIR', libexec_dir)

etc_dir = prefix / 'etc'
cdata.set_quoted('ETC_DIR', etc_dir)
cdata.set_quoted('PKGRUNDIR', etc_dir)
cdata.set_quoted('PKGLOCALSTATEDIR', etc_dir)

log_dir = prefix / 'logs'
cdata.set_quoted('LOG_DIR', log_dir)

help_dir = prefix / 'help'
cdata.set_quoted('HELP_DIR', help_dir)

module_dir = prefix / 'modules'
cdata.set_quoted('MODULE_DIR', module_dir)

cdata.set_quoted('PROGRAM_PREFIX', '')

subdir('include')
subdir('librb')
subdir('ircd')
subdir('modules')
subdir('extensions')
subdir('ssld')
subdir('bandb')
subdir('wsockd')
subdir('authd')
subdir('discordd')
subdir('tools')
subdir('doc')
subdir('help')

install_data('.ophion-keep', install_dir: log_dir)

# Determine the active TLS provider for the summary.
if wolfssl_dep.found()
  tls_provider = 'wolfssl'
elif mbedtls_dep.found()
  tls_provider = 'mbedtls'
elif gnutls_dep.found()
  tls_provider = 'gnutls'
else
  tls_provider = 'none (TLS disabled)'
endif

summary({
  'TLS provider':           tls_provider,
  'io_uring':               liburing_dep.found(),
  'sqlite3':                sqlite3_dep.found(),
  'hyperscan (filter ext)': hyperscan_dep.found(),
}, section: 'Dependencies', bool_yn: true)
