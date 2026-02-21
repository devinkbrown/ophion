# ---------------------------------------------------------------------------
# ophion-setup: interactive configuration wizard
# configure_file substitutes @ETC_DIR@ so that the installed script uses
# the correct ircd.conf path for whatever --prefix was given to meson.
# ---------------------------------------------------------------------------
setup_conf = configuration_data()
setup_conf.set('ETC_DIR', etc_dir)
setup_conf.set('LOG_DIR', log_dir)

configure_file(
  input: 'setup.py',
  output: 'ophion-setup',
  configuration: setup_conf,
  install: true,
  install_dir: get_option('bindir'),
  install_mode: 'rwxr-xr-x',
)

mkpasswd_exe = executable(meson.project_name() + '-mkpasswd',
  'mkpasswd.c',
  link_with: [librb_lib],
  install: true,
  install_rpath: get_option('libdir'),
  include_directories: [librb_inc])

mkfingerprint_exe = executable(meson.project_name() + '-mkfingerprint',
  'mkfingerprint.c',
  link_with: [librb_lib, ircd_lib],
  install: true,
  install_rpath: get_option('libdir'),
  include_directories: [librb_inc, base_inc])
