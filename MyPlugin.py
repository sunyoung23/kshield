import volatility.plugins.common as common
import volatility.plugins.filescan as filescan

import volatility.obj as obj
import volatility.poolscan as poolscan
import volatility.utils as utils
from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address
import os

class PoolScanFile(poolscan.PoolScanner):
    """Pool scanner for file objects"""

    def __init__(self, address_space):
        poolscan.PoolScanner.__init__(self, address_space)

        self.struct_name = "_FILE_OBJECT"
        self.object_type = "File"
        self.pooltag = obj.VolMagic(address_space).FilePoolTag.v()
        size = 0x98  # self.address_space.profile.get_obj_size("_FILE_OBJECT")

        self.checks = [
            ('CheckPoolSize', dict(condition=lambda x: x >= size)),
            ('CheckPoolType', dict(paged=False, non_paged=True, free=True)),
            ('CheckPoolIndex', dict(value=lambda x: x < 5)),
        ]

class MyPlugin(common.AbstractScanCommand):
    """Pool scanner for file objects"""

    scanners = [PoolScanFile]

    # Declare meta information associated with this plugin
    meta_info = {}
    meta_info['author'] = 'Andreas Schuster'
    meta_info['copyright'] = 'Copyright (c) 2009 Andreas Schuster'
    meta_info['contact'] = 'a.schuster@forensikblog.de'
    meta_info['license'] = 'GNU General Public License 2.0'
    meta_info['url'] = 'http://computer.forensikblog.de/en/'
    meta_info['os'] = 'WIN_32_XP_SP2'
    meta_info['version'] = '0.1'

    def render_text(self, outfd, data):
        self.table_header(outfd, [(self.offset_column(), '#018x'),
                                  ('#Ptr', '>6'),
                                  ('#Hnd', '>6'),
                                  ('Access', '>6'),
                                  ('Name', '')
                                  ])

        self.table_header(outfd, [('B', '#018x')
                                  ])

        for file in data:
            header = file.get_object_header()
            filename = file.file_name_with_device()
            if filename.endswith(('.xls','.doc')):
                print(filename)

            # self.table_row(outfd,
            #              file.obj_offset,
            #              header.PointerCount,
            #              header.HandleCount,
            #              file.access_string(),
            #              str(file.file_name_with_device() or ''))

            # self.table_row(outfd,
            #              file.obj_offset,
            #              header.PointerCount,
            #              header.HandleCount,
            #              file.access_string(),
            #              str(file.file_name_with_device() or ''))