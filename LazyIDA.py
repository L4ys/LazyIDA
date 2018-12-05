#encoding:utf8
from struct import unpack
import idaapi
import idautils
import idc
try:
    from idc_bc695 import *
except ImportError:
    pass

if idaapi.IDA_SDK_VERSION >= 690:
    from PyQt5.Qt import QApplication
else:
    from PySide.QtGui import QApplication

IDA7 = idaapi.IDA_SDK_VERSION >= 700
from enum import IntEnum
class EnumActionHandle(IntEnum):
    CONVERT_TO_STRING       = 0
    CONVERT_TO_HEX_STRING   = 1
    CONVERT_TO_CBYTE        = 2
    CONVERT_TO_CWORD        = 3
    CONVERT_TO_CDWORD       = 4
    CONVERT_TO_CQWORD       = 5
    CONVERT_TO_PYBYTE       = 6
    CONVERT_TO_PYWORD       = 7
    CONVERT_TO_PYDWORD      = 8
    CONVERT_TO_PYQWORD      = 9
    CONVERT_TO_GUID         = 10
    CONVERT_TO_SAVERAW      = 11

ACTION_CONVERT = ["lazyida:convert%d" % i for i in range(12)]
ACTION_SCANVUL = "lazyida:scanvul"
ACTION_COPYEA = "lazyida:copyea"
ACTION_XORDATA = "lazyida:xordata"
ACTION_FILLNOP = "lazyida:fillnop"

ACTION_HX_REMOVERETTYPE = "lazyida:hx_removerettype"
ACTION_HX_COPYEA = "lazyida:hx_copyea"
ACTION_HX_COPYNAME = "lazyida:hx_copyname"

u16 = lambda x: unpack("<H", x)[0]
u32 = lambda x: unpack("<I", x)[0]
u64 = lambda x: unpack("<Q", x)[0]

ARCH = 0
BITS = 0

import binascii
import re
from ctypes import *
class HexToGuid:
    def __init__(self, inputVal):
        """
        verification mem dump HEXstr len

        typedef struct _GUID {  // GUID struct
            unsigned long  Data1;
            unsigned short Data2;
            unsigned short Data3;
            unsigned char  Data4[ 8 ];
        } GUID;
        :param inputVal:
        """

        class GUID(Structure):
            _field_ = [
                ('Data1', c_uint32),
                ('Data2', c_uint16),
                ('Data3', c_uint16),
                ('Data4', c_char * 8)
            ]

        self.guid = GUID()
        self.guidStr = ''
        self.clsidStr = ''

        hexStr = self.getHexStr(inputVal)
        if hexStr is None:
            raise ValueError
        else:
            self.initGuid(hexStr)
            self.guidStr = self.getGuidStr()
            self.clsidStr = self.getClsidStr()

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return

    def getHexStr(self, inputVal):

        # return Value
        hexStr = None

        # Remove redundant characters
        redundants = '[\s\{\}\-\_]'
        replaceTo = ''
        inputVal = re.sub(redundants, replaceTo, inputVal)

        # validate input value
        guidPattern = '[a-fA-F0-9]{32}'
        match = re.match(guidPattern, inputVal)
        if match is not None:
            hexStr = match.group(0)

        return hexStr

    def initGuid(self, hexStr):
        """
        :param hexStr:HEX
        """

        # convert string to binaryData
        hexBinary = bytearray.fromhex(hexStr)
        self.guid.Data1, self.guid.Data2, self.guid.Data3, self.guid.Data4 = struct.unpack('<LHH8s', hexBinary)

    def getGuidStr(self):
        '''
        :return:  Guid
        '''

        # .decode('utf-8)' stands for removing b''
        guid = self.guid
        output = '%08x-%04x-%04x-%s' % (guid.Data1, guid.Data2, guid.Data3,
                                        binascii.hexlify(guid.Data4).decode('utf-8'))

        return output

    def getClsidStr(self):
        '''
        :return:  Clsid
        '''

        # .decode('utf-8)' stands for removing b''
        guid = self.guid
        output = '%08x-%04x-%04x-%s-%s' % (guid.Data1, guid.Data2, guid.Data3,
                                           binascii.hexlify(guid.Data4[0:2]).decode('utf-8'),
                                           binascii.hexlify(guid.Data4[2:]).decode('utf-8'))

        return output


def copy_to_clip(data):
    QApplication.clipboard().setText(data)

class VulnChoose(idaapi.Choose2):
    """
    Chooser class to display result of format string vuln scan
    """
    def __init__(self, title, items, icon, embedded=False):
        idaapi.Choose2.__init__(self, title, [["Address", 20], ["Function", 30], ["Format", 30]], embedded=embedded)
        self.items = items
        self.icon = 45

    def GetItems(self):
        return self.items

    def SetItems(self, items):
        self.items = [] if items is None else items

    def OnClose(self):
        pass

    def OnGetLine(self, n):
        return self.items[n]

    def OnGetSize(self):
        return len(self.items)

    def OnSelectLine(self, n):
        Jump(int(self.items[n][0], 16))

class hotkey_action_handler_t(idaapi.action_handler_t):
    """
    Action handler for hotkey actions
    """
    def __init__(self, action):
        idaapi.action_handler_t.__init__(self)
        self.action = action

    def activate(self, ctx):
        if self.action == ACTION_COPYEA:
            ea = ScreenEA()
            if ea != idaapi.BADADDR:
                copy_to_clip("0x%X" % ea)
                print "Address 0x%X has been copied to clipboard" % ea
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_FOR_FORM if ctx.form_type == idaapi.BWN_DISASM else idaapi.AST_DISABLE_FOR_FORM

class menu_action_handler_t(idaapi.action_handler_t):
    """
    Action handler for menu actions
    """
    def __init__(self, action):
        idaapi.action_handler_t.__init__(self)
        self.action = action

    def activate(self, ctx):
        if self.action in ACTION_CONVERT:
            # convert
            selection, start, end = idaapi.read_selection()
            if selection:
                size = end - start
            elif ItemSize(ScreenEA()) > 1:
                start = ScreenEA()
                size = ItemSize(start)
                end = start + size
            else:
                return False

            data = idaapi.get_many_bytes(start, size)
            name = Name(start)
            if not name:
                name = "data"
            if data:
                print "\n[+] Dump 0x%X - 0x%X (%u bytes) :" % (start, end, size)
                if self.action == ACTION_CONVERT[EnumActionHandle.CONVERT_TO_STRING]:
                    # escaped string
                    print '"%s"' % "".join("\\x%02X" % ord(b) for b in data)
                elif self.action == ACTION_CONVERT[EnumActionHandle.CONVERT_TO_HEX_STRING]:
                    # hex string
                    print "".join("%02X" % ord(b) for b in data)
                elif self.action == ACTION_CONVERT[EnumActionHandle.CONVERT_TO_CBYTE]:
                    # C array
                    output = "unsigned char %s[%d] = {" % (name, size)
                    for i in range(size):
                        if i % 16 == 0:
                            output += "\n    "
                        output += "0x%02X, " % ord(data[i])
                    output = output[:-2] + "\n};"
                    print output
                elif self.action == ACTION_CONVERT[EnumActionHandle.CONVERT_TO_CWORD]:
                    # C array word
                    data += "\x00"
                    array_size = (size + 1) / 2
                    output = "unsigned short %s[%d] = {" % (name, array_size)
                    for i in range(0, size, 2):
                        if i % 16 == 0:
                            output += "\n    "
                        output += "0x%04X, " % u16(data[i:i+2])
                    output = output[:-2] + "\n};"
                    print output
                elif self.action == ACTION_CONVERT[EnumActionHandle.CONVERT_TO_CDWORD]:
                    # C array dword
                    data += "\x00" * 3
                    array_size = (size + 3) / 4
                    output = "unsigned int %s[%d] = {" % (name, array_size)
                    for i in range(0, size, 4):
                        if i % 32 == 0:
                            output += "\n    "
                        output += "0x%08X, " % u32(data[i:i+4])
                    output = output[:-2] + "\n};"
                    print output
                elif self.action == ACTION_CONVERT[EnumActionHandle.CONVERT_TO_CQWORD]:
                    # C array qword
                    data += "\x00" * 7
                    array_size = (size + 7) / 8
                    output = "unsigned long %s[%d] = {" % (name, array_size)
                    for i in range(0, size, 8):
                        if i % 32 == 0:
                            output += "\n    "
                        output += "%#018X, " % u64(data[i:i+8])
                    output = output[:-2] + "\n};"
                    print output.replace("0X", "0x")
                elif self.action == ACTION_CONVERT[EnumActionHandle.CONVERT_TO_PYBYTE]:
                    # python list
                    print "[%s]" % ", ".join("0x%02X" % ord(b) for b in data)
                elif self.action == ACTION_CONVERT[EnumActionHandle.CONVERT_TO_PYWORD]:
                    # python list word
                    data += "\x00"
                    print "[%s]" % ", ".join("0x%04X" % u16(data[i:i+2]) for i in range(0, size, 2))
                elif self.action == ACTION_CONVERT[EnumActionHandle.CONVERT_TO_PYDWORD]:
                    # python list dword
                    data += "\x00" * 3
                    print "[%s]" % ", ".join("0x%08X" % u32(data[i:i+4]) for i in range(0, size, 4))
                elif self.action == ACTION_CONVERT[EnumActionHandle.CONVERT_TO_PYQWORD]:
                    # python list qword
                    data += "\x00" * 7
                    print "[%s]" %  ", ".join("%#016X" % u64(data[i:i+8]) for i in range(0, size, 8)).replace("0X", "0x")

                elif self.action == ACTION_CONVERT[EnumActionHandle.CONVERT_TO_GUID]:
                    # 2018.12.3 add LazyIDA ACTION_CONVERT:
                    # convert: char btBuf[0x10] => [GUID | UUID]
                    data = idaapi.get_many_bytes(start, 0x10)
                    print ("select data %s " % (",".join("0x%02X" % ord(b) for b in data)))

                    try:

                        with HexToGuid(("".join("%02X" % ord(b) for b in data))) as htg:
                            print('Google This!!!')
                            print('  GUID FORM : %s' % htg.guidStr)
                            print('  CLSID FORM : %s' % htg.clsidStr)
                    except ValueError:
                        print('Invalid hex value - %s' % (",".join("0x%02X" % ord(b) for b in data)))

                elif self.action == ACTION_CONVERT[EnumActionHandle.CONVERT_TO_SAVERAW]:
                    # 2018.12.3 add LazyIDA ACTION_CONVERT:
                    # save select Data to RawFile to cur work dir
                    # Raw File
                    # `AskFile(forsave, mask, prompt)`
                    # 默认工作目录为当前输入文件的工作目录
                    # forsave: 值为0或1, 0为启动一个 "打开"对话框, 1为启动一个"保存"对话框
                    # mask: 字符串, 为对话框的文件过滤器 比如: 过滤".dll" 则传入过滤字符串"*.dll"
                    # prompt:  字符串, 为对话框的"Title"

                    # idc.AskFile()
                    # print (idc.GetInputFilePath())  # 获得文件全路径
                    # print (idc.GetInputFile())      # 获得文件名
                    # lstFilePath = os.path.split(idc.GetInputFilePath())
                    # idc.SetInputFilePath()

                    if False:  # Open Dialog Ask To Save
                        strSaveFile = idc.AskFile(1, hex(start) + ".bin", "SaveRawFile As")
                        strSaveFile = os.path.split(strSaveFile)[-1]
                    else:
                        # strSaveFile = os.path.join(os.path.abspath(os.path.curdir), hex(start) + ".bin")  # 中文错误
                        strSaveFile = hex(start) + ".bin"  # save to work dir

                    print "SaveFile : %s" % os.path.join(os.path.abspath(os.path.curdir), strSaveFile)
                    # SaveFile(filepath, pos, ea, size):
                    retFlag = idc.SaveFile(strSaveFile, pos=0, ea=start, size=size)
                    if retFlag == 1:
                        print "SaveFile Finish!"
                    else:
                        print "SaveFileError!!!"

        elif self.action == ACTION_XORDATA:
            selection, start, end = idaapi.read_selection()
            if not selection:
                if ItemSize(ScreenEA()) > 1:
                    start = ScreenEA()
                    end = start + ItemSize(start)
                else:
                    return False

            data = idaapi.get_many_bytes(start, end - start)
            x = AskLong(0, "Xor with...")
            if x:
                x &= 0xFF
                print "\n[+] Xor 0x%X - 0x%X (%u bytes) with 0x%02X:" % (start, end, end - start, x)
                print repr("".join(chr(ord(b) ^ x) for b in data))
        elif self.action == ACTION_FILLNOP:
            selection, start, end = idaapi.read_selection()
            if selection:
                idaapi.patch_many_bytes(start, "\x90" * (end - start))
                print "\n[+] Fill 0x%X - 0x%X (%u bytes) with NOPs" % (start, end, end - start)
        elif self.action == ACTION_SCANVUL:
            print "\n[+] Finding Format String Vulnerability..."
            found = []
            for addr in idautils.Functions():
                name = GetFunctionName(addr)
                if "printf" in name and "v" not in name and SegName(addr) in (".text", ".plt", ".idata"):
                    xrefs = idautils.CodeRefsTo(addr, False)
                    for xref in xrefs:
                        vul = self.check_fmt_function(name, xref)
                        if vul:
                            found.append(vul)
            if found:
                print "[!] Done! %d possible vulnerabilities found." % len(found)
                ch = VulnChoose("Vulnerability", found, None, False)
                ch.Show()
            else:
                print "[-] No format string vulnerabilities found."
        else:
            return 0

        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

    @staticmethod
    def check_fmt_function(name, addr):
        """
        Check if the format string argument is not valid
        """
        function_head = GetFunctionAttr(addr, idc.FUNCATTR_START)

        while True:
            addr = idc.PrevHead(addr)
            op = GetMnem(addr).lower()
            dst = GetOpnd(addr, 0)

            if op in ("ret", "retn", "jmp", "b") or addr < function_head:
                return

            c = GetCommentEx(addr, 0)
            if c and c.lower() == "format":
                break
            elif name.endswith(("snprintf_chk",)):
                if op in ("mov", "lea") and dst.endswith(("r8", "r8d", "[esp+10h]")):
                    break
            elif name.endswith(("sprintf_chk",)):
                if op in ("mov", "lea") and (dst.endswith(("rcx", "[esp+0Ch]", "R3")) or
                                             dst.endswith("ecx") and BITS == 64):
                    break
            elif name.endswith(("snprintf", "fnprintf")):
                if op in ("mov", "lea") and (dst.endswith(("rdx", "[esp+8]", "R2")) or
                                             dst.endswith("edx") and BITS== 64):
                    break
            elif name.endswith(("sprintf", "fprintf", "dprintf", "printf_chk")):
                if op in ("mov", "lea") and (dst.endswith(("rsi", "[esp+4]", "R1")) or
                                             dst.endswith("esi") and BITS == 64):
                    break
            elif name.endswith("printf"):
                if op in ("mov", "lea") and (dst.endswith(("rdi", "[esp]", "R0")) or
                                             dst.endswith("edi") and BITS == 64):
                    break

        # format arg found, check its type and value
        # get last oprend
        op_index = GetDisasm(addr).count(",")
        op_type = GetOpType(addr, op_index)
        opnd = GetOpnd(addr, op_index)

        if op_type == o_reg:
            # format is in register, try to track back and get the source
            _addr = addr
            while True:
                _addr = idc.PrevHead(_addr)
                _op = GetMnem(_addr).lower()
                if _op in ("ret", "retn", "jmp", "b") or _addr < function_head:
                    break
                elif _op in ("mov", "lea", "ldr") and GetOpnd(_addr, 0) == opnd:
                    op_type = GetOpType(_addr, 1)
                    opnd = GetOpnd(_addr, 1)
                    addr = _addr
                    break

        if op_type == o_imm or op_type == o_mem:
            # format is a memory address, check if it's in writable segment
            op_addr = GetOperandValue(addr, op_index)
            seg = idaapi.getseg(op_addr)
            if seg:
                if not seg.perm & idaapi.SEGPERM_WRITE:
                    # format is in read-only segment
                    return

        print "0x%X: Possible Vulnerability: %s, format = %s" % (addr, name, opnd)
        return ["0x%X" % addr, name, opnd]

class hexrays_action_handler_t(idaapi.action_handler_t):
    """
    Action handler for hexrays actions
    """
    def __init__(self, action):
        idaapi.action_handler_t.__init__(self)
        self.action = action
        self.ret_type = {}

    def activate(self, ctx):
        if self.action == ACTION_HX_REMOVERETTYPE:
            if IDA7:
                vdui = idaapi.get_widget_vdui(ctx.widget)
            else:
                vdui = idaapi.get_tform_vdui(ctx.form)
            self.remove_rettype(vdui)
            vdui.refresh_ctext()
        elif self.action == ACTION_HX_COPYEA:
            ea = idaapi.get_screen_ea()
            if ea != idaapi.BADADDR:
                copy_to_clip("0x%X" % ea)
                print "Address 0x%X has been copied to clipboard" % ea
        elif self.action == ACTION_HX_COPYNAME:
            if IDA7:
                name = idaapi.get_highlight(idaapi.get_current_viewer())[0]
            else:
                name = idaapi.get_highlighted_identifier()
            if name:
                copy_to_clip(name)
                print "%s has been copied to clipboard" % name
        else:
            return 0

        return 1

    def update(self, ctx):
        if IDA7:
            vdui = idaapi.get_widget_vdui(ctx.widget)
            return idaapi.AST_ENABLE_FOR_WIDGET if vdui else idaapi.AST_DISABLE_FOR_WIDGET
        vdui = idaapi.get_tform_vdui(ctx.form)
        return idaapi.AST_ENABLE_FOR_FORM if vdui else idaapi.AST_DISABLE_FOR_FORM

    def remove_rettype(self, vu):
        if vu.item.citype == idaapi.VDI_FUNC:
            # current function
            ea = vu.cfunc.entry_ea
            old_func_type = idaapi.tinfo_t()
            if not vu.cfunc.get_func_type(old_func_type):
                return False
        elif vu.item.citype == idaapi.VDI_EXPR and vu.item.e.is_expr() and vu.item.e.type.is_funcptr():
            # call xxx
            ea = vu.item.get_ea()
            old_func_type = idaapi.tinfo_t()

            func = idaapi.get_func(ea)
            if func:
                try:
                    cfunc = idaapi.decompile(func)
                except idaapi.DecompilationFailure:
                    return False

                if not cfunc.get_func_type(old_func_type):
                    return False
            else:
                return False
        else:
            return False

        fi = idaapi.func_type_data_t()
        if ea != idaapi.BADADDR and old_func_type.get_func_details(fi):
            # Return type is already void
            if fi.rettype.is_decl_void():
                # Restore ret type
                if ea not in self.ret_type:
                    return True
                ret = self.ret_type[ea]
            else:
                # Save ret type and change it to void
                self.ret_type[ea] = fi.rettype
                ret = idaapi.BT_VOID

            # Create new function info with new rettype
            fi.rettype = idaapi.tinfo_t(ret)

            # Create new function type with function info
            new_func_type = idaapi.tinfo_t()
            new_func_type.create_func(fi)

            # Apply new function type
            if idaapi.apply_tinfo2(ea, new_func_type, idaapi.TINFO_DEFINITE):
                return vu.refresh_view(True)

        return False

class UI_Hook(idaapi.UI_Hooks):
    def __init__(self):
        idaapi.UI_Hooks.__init__(self)

    def finish_populating_tform_popup(self, form, popup):
        form_type = idaapi.get_tform_type(form)

        if form_type == idaapi.BWN_DISASM or form_type == idaapi.BWN_DUMP:
            if idaapi.read_selection() or ItemSize(ScreenEA()) > 1:
                idaapi.attach_action_to_popup(form, popup, ACTION_XORDATA, None)
                idaapi.attach_action_to_popup(form, popup, ACTION_FILLNOP, None)
                for action in ACTION_CONVERT:
                    idaapi.attach_action_to_popup(form, popup, action, "Convert/")

        if form_type == idaapi.BWN_DISASM and (ARCH, BITS) in [(idaapi.PLFM_386, 32),
                                                               (idaapi.PLFM_386, 64),
                                                               (idaapi.PLFM_ARM, 32),]:
            idaapi.attach_action_to_popup(form, popup, ACTION_SCANVUL, None)

class HexRays_Hook(object):
    def callback(self, event, *args):
        if event == idaapi.hxe_populating_popup:
            form, phandle, vu = args
            if vu.item.citype == idaapi.VDI_FUNC or (vu.item.citype == idaapi.VDI_EXPR and vu.item.e.is_expr() and vu.item.e.type.is_funcptr()):
                idaapi.attach_action_to_popup(form, phandle, ACTION_HX_REMOVERETTYPE, None)
        elif event == idaapi.hxe_double_click:
            vu, shift_state = args
            # auto jump to target if clicked item is xxx->func();
            if vu.item.citype == idaapi.VDI_EXPR and vu.item.e.is_expr():
                expr = idaapi.tag_remove(vu.item.e.print1(None))
                if "->" in expr:
                    # find target function
                    name = expr.split("->")[-1]
                    addr = LocByName(name)
                    if addr == idaapi.BADADDR:
                        # try class::function
                        e = vu.item.e
                        while e.x:
                            e = e.x
                        addr = LocByName("%s::%s" % (str(e.type).split()[0], name))

                    if addr != idaapi.BADADDR:
                        Jump(addr)
                        return 1
        return 0

class LazyIDA_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_HIDE
    comment = "LazyIDA"
    help = ""
    wanted_name = "LazyIDA"
    wanted_hotkey = ""

    def init(self):
        self.hexrays_inited = False
        self.registered_actions = []
        self.registered_hx_actions = []

        global ARCH
        global BITS
        ARCH = idaapi.ph_get_id()
        info = idaapi.get_inf_structure()
        if info.is_64bit():
            BITS = 64
        elif info.is_32bit():
            BITS = 32
        else:
            BITS = 16

        print "LazyIDA (v1.0.0.3) plugin has been loaded."

        # Register menu actions
        menu_actions = (
            idaapi.action_desc_t(ACTION_CONVERT[EnumActionHandle.CONVERT_TO_STRING],        "Convert to string",                menu_action_handler_t(ACTION_CONVERT[EnumActionHandle.CONVERT_TO_STRING]), None, None, 80),
            idaapi.action_desc_t(ACTION_CONVERT[EnumActionHandle.CONVERT_TO_HEX_STRING],    "Convert to hex string",            menu_action_handler_t(ACTION_CONVERT[EnumActionHandle.CONVERT_TO_HEX_STRING]), None, None, 8),
            idaapi.action_desc_t(ACTION_CONVERT[EnumActionHandle.CONVERT_TO_CBYTE],         "Convert to C/C++ array (BYTE)",    menu_action_handler_t(ACTION_CONVERT[EnumActionHandle.CONVERT_TO_CBYTE]),   None, None, 38),
            idaapi.action_desc_t(ACTION_CONVERT[EnumActionHandle.CONVERT_TO_CWORD],         "Convert to C/C++ array (WORD)",    menu_action_handler_t(ACTION_CONVERT[EnumActionHandle.CONVERT_TO_CWORD]),   None, None, 38),
            idaapi.action_desc_t(ACTION_CONVERT[EnumActionHandle.CONVERT_TO_CDWORD],        "Convert to C/C++ array (DWORD)",   menu_action_handler_t(ACTION_CONVERT[EnumActionHandle.CONVERT_TO_CDWORD]),  None, None, 38),
            idaapi.action_desc_t(ACTION_CONVERT[EnumActionHandle.CONVERT_TO_CQWORD],        "Convert to C/C++ array (QWORD)",   menu_action_handler_t(ACTION_CONVERT[EnumActionHandle.CONVERT_TO_CQWORD]),  None, None, 38),
            idaapi.action_desc_t(ACTION_CONVERT[EnumActionHandle.CONVERT_TO_PYBYTE],        "Convert to python list (BYTE)",    menu_action_handler_t(ACTION_CONVERT[EnumActionHandle.CONVERT_TO_PYBYTE]),  None, None, 201),
            idaapi.action_desc_t(ACTION_CONVERT[EnumActionHandle.CONVERT_TO_PYWORD],        "Convert to python list (WORD)",    menu_action_handler_t(ACTION_CONVERT[EnumActionHandle.CONVERT_TO_PYWORD]),  None, None, 201),
            idaapi.action_desc_t(ACTION_CONVERT[EnumActionHandle.CONVERT_TO_PYDWORD],       "Convert to python list (DWORD)",   menu_action_handler_t(ACTION_CONVERT[EnumActionHandle.CONVERT_TO_PYDWORD]), None, None, 201),
            idaapi.action_desc_t(ACTION_CONVERT[EnumActionHandle.CONVERT_TO_PYQWORD],       "Convert to python list (QWORD)",   menu_action_handler_t(ACTION_CONVERT[EnumActionHandle.CONVERT_TO_PYQWORD]), None, None, 201),
            idaapi.action_desc_t(ACTION_CONVERT[EnumActionHandle.CONVERT_TO_GUID],          "Convert to GUID",                  menu_action_handler_t(ACTION_CONVERT[EnumActionHandle.CONVERT_TO_GUID]),    None, None, 8),
            idaapi.action_desc_t(ACTION_CONVERT[EnumActionHandle.CONVERT_TO_SAVERAW],       "Save To File(RAW)",                menu_action_handler_t(ACTION_CONVERT[EnumActionHandle.CONVERT_TO_SAVERAW]), None, None, 8),
            idaapi.action_desc_t(ACTION_XORDATA,                                            "Get xored data",                   menu_action_handler_t(ACTION_XORDATA), None, None, 9),
            idaapi.action_desc_t(ACTION_FILLNOP,                                            "Fill with NOPs",                   menu_action_handler_t(ACTION_FILLNOP), None, None, 9),
            idaapi.action_desc_t(ACTION_SCANVUL,                                            "Scan format string vulnerabilities", menu_action_handler_t(ACTION_SCANVUL), None, None, 160),
        )
        for action in menu_actions:
            idaapi.register_action(action)
            self.registered_actions.append(action.name)

        # Register hotkey actions
        hotkey_actions = (
            idaapi.action_desc_t(ACTION_COPYEA, "Copy EA", hotkey_action_handler_t(ACTION_COPYEA), "w", "Copy current EA", 0),
        )
        for action in hotkey_actions:
            idaapi.register_action(action)
            self.registered_actions.append(action.name)

        # Add ui hook
        self.ui_hook = UI_Hook()
        self.ui_hook.hook()

        # Add hexrays ui callback
        if idaapi.init_hexrays_plugin():
            addon = idaapi.addon_info_t()
            addon.id = "tw.l4ys.lazyida"
            addon.name = "LazyIDA"
            addon.producer = "Lays"
            addon.url = "https://github.com/L4ys/LazyIDA"
            addon.version = "1.0.0.3"
            idaapi.register_addon(addon)

            hx_actions = (
                idaapi.action_desc_t(ACTION_HX_REMOVERETTYPE, "Remove return type", hexrays_action_handler_t(ACTION_HX_REMOVERETTYPE), "v"),
                idaapi.action_desc_t(ACTION_HX_COPYEA, "Copy ea", hexrays_action_handler_t(ACTION_HX_COPYEA), "w"),
                idaapi.action_desc_t(ACTION_HX_COPYNAME, "Copy name", hexrays_action_handler_t(ACTION_HX_COPYNAME), "c"),
            )
            for action in hx_actions:
                idaapi.register_action(action)
                self.registered_hx_actions.append(action.name)

            self.hx_hook = HexRays_Hook()
            idaapi.install_hexrays_callback(self.hx_hook.callback)
            self.hexrays_inited = True

        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        pass

    def term(self):
        if self.ui_hook:
            self.ui_hook.unhook()

        # Unregister actions
        for action in self.registered_actions:
            idaapi.unregister_action(action)

        if self.hexrays_inited:
            # Unregister hexrays actions
            for action in self.registered_hx_actions:
                idaapi.unregister_action(action)
            if self.hx_hook:
                idaapi.remove_hexrays_callback(self.hx_hook.callback)
            idaapi.term_hexrays_plugin()

def PLUGIN_ENTRY():
    return LazyIDA_t()

