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

# TLS: wolfSSL is the sole TLS provider.  It exposes an OpenSSL-compatible
# API so the existing openssl.c backend is reused as-is.
wolfssl_dep = dependency('wolfssl', required: true)

cdata.set('HAVE_WOLFSSL', true)
cdata.set('HAVE_OPENSSL', true)   # openssl.c compiled via wolfSSL compat layer
cdata.set('HAVE_LIBCRYPTO', true)

# Expose wolfSSL's compat headers as <openssl/...> and ensure wolfssl/options.h
# is force-included before any compat header so OPENSSL_EXTRA et al. are set.
wolfssl_inc = run_command('pkg-config', '--variable=includedir', 'wolfssl',
  check: true).stdout().strip()
add_project_arguments('-I' + wolfssl_inc / 'wolfssl', language: 'c')
add_project_arguments('-include', 'wolfssl/options.h', language: 'c')

libssl_dep = wolfssl_dep

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
  ['HAVE_NANOSLEEP', 'nanosleep', 'time.h'],
  ['HAVE_CLOCK_NANOSLEEP', 'clock_nanosleep', 'time.h'],
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
  ['HAVE_ARC4RANDOM_BUF', 'arc4random_buf', 'stdlib.h'],
  ['HAVE_GETRANDOM', 'getrandom', 'sys/random.h'],
  ['HAVE_GETENTROPY', 'getentropy', 'unistd.h'],
  ['HAVE_GETRUSAGE', 'getrusage', 'sys/resource.h'],
  ['HAVE_TIMERFD_CREATE', 'timerfd_create', 'sys/timerfd.h'],
  ['HAVE_CLOCK_GETTIME', 'clock_gettime', 'time.h'],
]

foreach f : check_functions
  if cc.has_function(f.get(1), prefix : '#include <' + f.get(2) + '>') and cc.has_header_symbol(f.get(2), f.get(1))
    cdata.set(f.get(0), 1)
  endif
endforeach

# GNU-extension functions that require _GNU_SOURCE to be visible in headers.
# Checked separately with an explicit prefix so they're found on Linux.
gnu_ext_functions = [
  ['HAVE_ACCEPT4', 'accept4', 'sys/socket.h'],
  ['HAVE_PIPE2',   'pipe2',   'unistd.h'],
]
foreach f : gnu_ext_functions
  if cc.has_function(f.get(1),
       prefix : '#define _GNU_SOURCE 1\n#include <' + f.get(2) + '>')
    cdata.set(f.get(0), 1)
  endif
endforeach

# Socket constants checked as header symbols (not functions).
if cc.has_header_symbol('sys/socket.h', 'SO_NOSIGPIPE')
  cdata.set('HAVE_SO_NOSIGPIPE', 1)
endif

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

tls_provider = 'wolfssl ' + run_command('pkg-config', '--modversion', 'wolfssl',
  check: true).stdout().strip()

summary({
  'TLS provider':           tls_provider,
  'io_uring':               liburing_dep.found(),
  'sqlite3':                sqlite3_dep.found(),
  'hyperscan (filter ext)': hyperscan_dep.found(),
}, section: 'Dependencies', bool_yn: true)
