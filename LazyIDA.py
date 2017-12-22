import idaapi
from struct import unpack

if idaapi.IDA_SDK_VERSION >= 690:
    from PyQt5.Qt import QApplication
else:
    from PySide.QtGui import QApplication

IDA7 = idaapi.IDA_SDK_VERSION >= 700
ACTION_CONVERT = ["lazyida:convert%d" % i for i in range(14)]
ACTION_SCANVUL = "lazyida:scanvul"
ACTION_COPYEA = "lazyida:copyea"
ACTION_XORDATA = "lazyida:xordata"
ACTION_FILLNOP = "lazyida:fillnop"

ACTION_HX_REMOVERETTYPE = "lazyida:hx_removerettype"
ACTION_HX_COPYEA = "lazyida:hx_copyea"
ACTION_HX_COPYNAME = "lazyida:hx_copyname"

NETNODE_NAME = "$ lazyida-hx-remove_rettype"

u16 = lambda x: unpack("<H", x)[0]
u32 = lambda x: unpack("<I", x)[0]
u64 = lambda x: unpack("<Q", x)[0]

arch = 0
bits = 0
node = idaapi.netnode()
ret_type = {}

def copy_to_clip(data):
    QApplication.clipboard().setText(data)

def save_ret_type(addr, type):
    ret_type[addr] = type;
    node.setblob(repr(ret_type), 0, 'I')

class VulnChoose(Choose2):
    """
    Chooser class to display result of format string vuln scan
    """
    def __init__(self, title, items, icon, embedded=False):
        Choose2.__init__(self, title, [["Address", 20], ["Function", 30], ["Format",30]], embedded=embedded)
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
            if data:
                print "\n[+] Dump 0x%X - 0x%X (%u bytes) :" % ( start, end, size )
                if self.action == ACTION_CONVERT[0]:
                    # escaped string
                    output = '"'
                    output += "".join("\\x%02X" % ord(b) for b in data)
                    output += '"'
                    print output
                elif self.action == ACTION_CONVERT[1]:
                    # hex string
                    print "".join("%02X" % ord(b) for b in data)
                elif self.action == ACTION_CONVERT[2]:
                    # C array
                    output = "unsigned char data[%d] = {" % size
                    j = 0
                    for i in range(size):
                        if j % 16 == 0:
                            output += "\n    "
                        j += 1
                        output += "0x%02X, " % ord(data[i])
                    output = output[:-2]
                    output += "\n};"
                    print output
                elif self.action == ACTION_CONVERT[3]:
                    # C array word
                    data += "\x00"
                    array_size = (size + 1) / 2
                    output = "unsigned short data[%d] = {" % array_size
                    j = 0
                    for i in range(0, size, 2):
                        if j % 8 == 0:
                            output += "\n    "
                        j += 1
                        output += "0x%04X, " % u16(data[i:i+2])
                    output = output[:-2]
                    output += "\n};"
                    print output
                elif self.action == ACTION_CONVERT[4]:
                    # C array dword
                    data += "\x00" * 3
                    array_size = (size + 3) / 4
                    output = "unsigned int data[%d] = {" % array_size
                    j = 0
                    for i in range(0, size, 4):
                        if j % 8 == 0:
                            output += "\n    "
                        j += 1
                        output += "0x%08X, " % u32(data[i:i+4])
                    output = output[:-2]
                    output += "\n};"
                    print output
                elif self.action == ACTION_CONVERT[5]:
                    # C array qword
                    data += "\x00" * 7
                    array_size = (size + 7) / 8
                    output = "unsigned long data[%d] = {" % array_size
                    j = 0
                    for i in range(0, size, 8):
                        if j % 4 == 0:
                            output += "\n    "
                        j += 1
                        output += "%#018X, " % u64(data[i:i+8])
                    output = output[:-2]
                    output += "\n};"
                    print output.replace("0X", "0x")
                elif self.action == ACTION_CONVERT[6]:
                    # python list
                    output = "["
                    output += ",".join("0x%02X" % ord(b) for b in data)
                    output += "]"
                    print output
                elif self.action == ACTION_CONVERT[7]:
                    # python list word
                    data += "\x00"
                    output = "["
                    output += ",".join("0x%04X" % u16(data[i:i+2]) for i in range(0, size, 2))
                    output += "]"
                    print output
                elif self.action == ACTION_CONVERT[8]:
                    # python list dword
                    data += "\x00" * 3
                    output = "["
                    output += ",".join("0x%08X" % u32(data[i:i+4]) for i in range(0, size, 4))
                    output += "]"
                    print output
                elif self.action == ACTION_CONVERT[9]:
                    # python list qword
                    data += "\x00" * 7
                    output = "["
                    output += ",".join("%#018X" % u64(data[i:i+8]) for i in range(0, size, 8))
                    output += "]"
                    print output.replace("0X", "0x")
                elif self.action == ACTION_CONVERT[10]:
                    # java byte array
                    output = "byte[] data = new byte[] {"
                    j = 0
                    for i in range(size):
                        if j % 8 == 0:
                            output += "\n    "
                        j += 1
                        output += "(byte) 0x%02x, " % ord(data[i])
                    output = output[:-2]
                    output += "\n};"
                    print output
                elif self.action == ACTION_CONVERT[11]:
                    # java short array
                    data += "\x00"
                    array_size = (size + 1) / 2
                    output = "short[] data = new short[] {"
                    j = 0
                    for i in range(0, size, 2):
                        if j % 8 == 0:
                            output += "\n    "
                        j += 1
                        output += "(short) 0x%04x, " % u16(data[i:i+2])
                    output = output[:-2]
                    output += "\n};"
                    print output
                elif self.action == ACTION_CONVERT[12]:
                    # java int array
                    data += "\x00" * 3
                    array_size = (size + 3) / 4
                    output = "int[] data = new int[] {"
                    j = 0
                    for i in range(0, size, 4):
                        if j % 8 == 0:
                            output += "\n    "
                        j += 1
                        output += "0x%08x, " % u32(data[i:i+4])
                    output = output[:-2]
                    output += "\n};"
                    print output
                elif self.action == ACTION_CONVERT[13]:
                    # java long array
                    data += "\x00" * 7
                    array_size = (size + 7) / 8
                    output = "long[] data = new long[] {"
                    j = 0
                    for i in range(0, size, 8):
                        if j % 4 == 0:
                            output += "\n    "
                        j += 1
                        output += "%#018xL, " % u64(data[i:i+8])
                    output = output[:-2]
                    output += "\n};"
                    print output.replace("0X", "0x")
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
                print "\n[+] Xor 0x%X - 0x%X (%u bytes) with 0x%02X:" % ( start, end, end - start, x )
                print repr("".join(chr(ord(b) ^ x) for b in data))
        elif self.action == ACTION_FILLNOP:
            selection, start, end = idaapi.read_selection()
            if selection:
                idaapi.patch_many_bytes(start, "\x90" * (end - start))
                print "\n[+] Fill 0x%X - 0x%X (%u bytes) with NOPs" % ( start, end, end - start )
        elif self.action == ACTION_SCANVUL:
            print "\n[+] Finding Format String Vulnerability..."
            found = []
            for addr in Functions():
                name = GetFunctionName(addr)
                if "printf" in name and "v" not in name and SegName(addr) in (".text", ".plt", ".idata"):
                    xrefs = CodeRefsTo(addr, False)
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
                if op in ("mov", "lea") and ( dst.endswith(("rcx", "[esp+0Ch]", "R3")) or
                                              dst.endswith("ecx") and bits == 64 ):
                    break
            elif name.endswith(("snprintf", "fnprintf")):
                if op in ("mov", "lea") and ( dst.endswith(("rdx", "[esp+8]", "R2")) or
                                              dst.endswith("edx") and bits == 64 ):
                    break
            elif name.endswith(("sprintf", "fprintf", "dprintf", "printf_chk")):
                if op in ("mov", "lea") and ( dst.endswith(("rsi", "[esp+4]", "R1")) or
                                              dst.endswith("esi") and bits == 64 ):
                    break
            elif name.endswith("printf"):
                if op in ("mov", "lea") and ( dst.endswith(("rdi", "[esp]", "R0")) or
                                              dst.endswith("edi") and bits == 64 ):
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
        else:
            vdui = idaapi.get_tform_vdui(ctx.form)
            return idaapi.AST_ENABLE_FOR_FORM if vdui else idaapi.AST_DISABLE_FOR_FORM


    @staticmethod
    def remove_rettype(vu):
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
                if ea not in ret_type:
                    return True
                ret = ret_type[ea]
            else:
                # Save ret type and change it to void
                ret_type[ea] = fi.rettype
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

        if form_type == idaapi.BWN_DISASM and (arch, bits) in [(idaapi.PLFM_386, 32),
                                                               (idaapi.PLFM_386, 64),
                                                               (idaapi.PLFM_ARM, 32),]:
            idaapi.attach_action_to_popup(form, popup, ACTION_SCANVUL, None)

class HexRays_Hook():
    def callback(self, event, *args):
        if event == idaapi.hxe_populating_popup:
            form, phandle, vu = args
            if vu.item.citype == idaapi.VDI_FUNC or ( vu.item.citype == idaapi.VDI_EXPR and vu.item.e.is_expr() and vu.item.e.type.is_funcptr() ):
                idaapi.attach_action_to_popup(form, phandle, ACTION_HX_REMOVERETTYPE, None)

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

        global arch
        global bits
        arch = idaapi.ph_get_id()
        info = idaapi.get_inf_structure()
        if info.is_64bit():
            bits = 64
        elif info.is_32bit():
            bits = 32
        else:
            bits = 16

        global node
        global ret_type
        if not node.create(NETNODE_NAME):
            # node exists
            data = node.getblob(0, 'I')
            if data:
                ret_type = eval(data)

        print "LazyIDA (Python Version) (v1.0.0.2) plugin has been loaded."

        # Register menu actions
        menu_actions = (
            idaapi.action_desc_t(ACTION_CONVERT[0], "Convert to string", menu_action_handler_t(ACTION_CONVERT[0]), None, None, 80),
            idaapi.action_desc_t(ACTION_CONVERT[1], "Convert to hex string", menu_action_handler_t(ACTION_CONVERT[1]), None, None, 8),
            idaapi.action_desc_t(ACTION_CONVERT[2], "Convert to C/C++ array (BYTE)", menu_action_handler_t(ACTION_CONVERT[2]), None, None, 38),
            idaapi.action_desc_t(ACTION_CONVERT[3], "Convert to C/C++ array (WORD)", menu_action_handler_t(ACTION_CONVERT[3]), None, None, 38),
            idaapi.action_desc_t(ACTION_CONVERT[4], "Convert to C/C++ array (DWORD)", menu_action_handler_t(ACTION_CONVERT[4]), None, None, 38),
            idaapi.action_desc_t(ACTION_CONVERT[5], "Convert to C/C++ array (QWORD)", menu_action_handler_t(ACTION_CONVERT[5]), None, None, 38),
            idaapi.action_desc_t(ACTION_CONVERT[6], "Convert to python list (BYTE)", menu_action_handler_t(ACTION_CONVERT[6]), None, None, 201),
            idaapi.action_desc_t(ACTION_CONVERT[7], "Convert to python list (WORD)", menu_action_handler_t(ACTION_CONVERT[7]), None, None, 201),
            idaapi.action_desc_t(ACTION_CONVERT[8], "Convert to python list (DWORD)", menu_action_handler_t(ACTION_CONVERT[8]), None, None, 201),
            idaapi.action_desc_t(ACTION_CONVERT[9], "Convert to python list (QWORD)", menu_action_handler_t(ACTION_CONVERT[9]), None, None, 201),
            idaapi.action_desc_t(ACTION_CONVERT[10], "Convert to java array (BYTE)", menu_action_handler_t(ACTION_CONVERT[10]), None, None, 15),
            idaapi.action_desc_t(ACTION_CONVERT[11], "Convert to java array (WORD)", menu_action_handler_t(ACTION_CONVERT[11]), None, None, 15),
            idaapi.action_desc_t(ACTION_CONVERT[12], "Convert to java array (DWORD)", menu_action_handler_t(ACTION_CONVERT[12]), None, None, 15),
            idaapi.action_desc_t(ACTION_CONVERT[13], "Convert to java array (QWORD)", menu_action_handler_t(ACTION_CONVERT[13]), None, None, 15),
            idaapi.action_desc_t(ACTION_XORDATA, "Get xored data", menu_action_handler_t(ACTION_XORDATA), None, None, 9),
            idaapi.action_desc_t(ACTION_FILLNOP, "Fill with NOPs", menu_action_handler_t(ACTION_FILLNOP), None, None, 9),
            idaapi.action_desc_t(ACTION_SCANVUL, "Scan format string vulnerabilities", menu_action_handler_t(ACTION_SCANVUL), None, None, 160),
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
            hx_actions = (
                idaapi.action_desc_t(ACTION_HX_REMOVERETTYPE, "Remove return type", hexrays_action_handler_t(ACTION_HX_REMOVERETTYPE), "v"),
                idaapi.action_desc_t(ACTION_HX_COPYEA , "Copy ea", hexrays_action_handler_t(ACTION_HX_COPYEA), "w"),
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
