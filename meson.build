project('qwfwd', 'c')

if meson.get_compiler('c').get_id() == 'gcc'
    add_global_link_arguments('-static-libgcc', language: 'c')
endif

qwfwd_sources = [
    'ban.c',
    'clc.c',
    'cmd.c',
    'cvar.c',
    'fs.c',
    'huff.c',
    'info.c',
    'main.c',
    'msg.c',
    'net.c',
    'peer.c',
    'query.c',
    'svc.c',
    'sys.c',
    'token.c',
]

executable('qwfwd', qwfwd_sources,
    dependencies : [
        meson.get_compiler('c').find_library('ws2_32', required : false)
    ]
)
