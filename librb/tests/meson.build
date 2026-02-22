test_patricia = executable('test_patricia',
  'test_patricia.c',
  dependencies: [],
  link_with: librb_lib,
  include_directories: [librb_inc],
)

test('patricia', test_patricia)

test_uring = executable('test_uring',
  'test_uring.c',
  dependencies: [liburing_dep],
  link_with: librb_lib,
  include_directories: [librb_inc],
)

test('uring', test_uring)
