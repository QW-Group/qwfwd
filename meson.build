project('qwfwd', 'c')

if meson.get_compiler('c').get_id() == 'gcc'
    add_global_link_arguments('-static-libgcc', language: 'c')
endif

qwfwd_sources = [
    'src/ban.c',
    'src/clc.c',
    'src/cmd.c',
    'src/cvar.c',
    'src/fs.c',
    'src/huff.c',
    'src/info.c',
    'src/main.c',
    'src/msg.c',
    'src/net.c',
    'src/peer.c',
    'src/query.c',
    'src/svc.c',
    'src/sys.c',
    'src/token.c',
]

executable('qwfwd', qwfwd_sources,
    dependencies : [
        meson.get_compiler('c').find_library('ws2_32', required : false)
    ]
)
