extension_dir = module_dir / 'extensions'

extensions = [
  'chantype_dummy',
  'createauthonly',
  'createoperonly',
  'force_user_invis',
  'helpops',
  'hurt',
  'invite_notify',
  'ip_cloaking_unified',
  'restrict-unauthenticated',
  'm_adminwall',
  'm_echotags',
  'm_extendchans',
  'm_findforwards',
  'm_locops',
  'm_mkpasswd',
  'm_sendbans',
  'm_roleplay',
  'hide_uncommon_channels',
  'no_kill_services',
  'no_locops',
  'no_oper_invis',
  'drain',
  'example_module'
]

foreach extension : extensions
  shared_module(extension,
    '@0@.c'.format(extension),
    link_with: [librb_lib, ircd_lib],
    include_directories: [librb_inc, base_inc],
    name_prefix: '',
    install: true,
    install_dir: extension_dir)
endforeach

hyperscan_dep = dependency('hyperscan', required: false)

if hyperscan_dep.found()
  shared_module('filter',
    'filter.c',
    dependencies: [hyperscan_dep],
    link_with: [librb_lib, ircd_lib],
    include_directories: [librb_inc, base_inc],
    name_prefix: '',
    install: true,
    install_dir: extension_dir)
endif
