import idaapi
import subprocess
from struct import unpack

ACTION_CONVERT = ["lazyida:convert%d" % i for i in range(8)]
ACTION_SCANVUL = "lazyida:scanvul"
ACTION_COPYEA = "lazyida:copyea"
ACTION_XORDATA = "lazyida:xordata"

ACTION_HX_REMOVERETTYPE = "lazyida:hx_removerettype"
ACTION_HX_COPYEA = "lazyida:hx_copyea"
ACTION_HX_COPYNAME = "lazyida:hx_copyname"

cgc_syscall_map = {
    "LINUX - sys_exit": "CGC - _terminate",
    "LINUX - sys_fork": "CGC - transmit",
    "LINUX - sys_read": "CGC - receive",
    "LINUX - sys_write": "CGC - fdwait",
    "LINUX - sys_open": "CGC - allocate",
    "LINUX - sys_close": "CGC - deallocate",
    "LINUX - sys_waitpid": "CGC - random",
    "LINUX - ": "CGC - receive",
}

cgc_syscall_type_map = {
    "__terminate": "void _terminate(int status);",
    "_transmit": "int transmit(int fd, const void *buf, size_t count, size_t *tx_bytes);",
    "_receive": "int receive(int fd, void *buf, size_t count, size_t *rx_bytes);",
    "_fdwait": "int fdwait(int nfds, fd_set *readfds, fd_set *writefds, const struct timeval *timeout, int *readyfds);",
    "_allocate": "int allocate(size_t length, int is_X, void **addr);",
    "_deallocate": "int deallocate(void *addr, size_t length);",
    "_random": "int random(void *buf, size_t count, size_t *rnd_bytes);",
}

u32 = lambda x: unpack("<I", x)[0]
u64 = lambda x: unpack("<Q", x)[0]

is_cgc = False
arch = 0
bits = 0

def copy_to_clip(data):
    subprocess.call('echo|set /p="%s"|clip' % data, shell=True)

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
                elif self.action == ACTION_CONVERT[4]:
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
                elif self.action == ACTION_CONVERT[5]:
                    # python list
                    output = "["
                    output += ",".join("0x%02X" % ord(b) for b in data)
                    output += "]"
                    print output
                elif self.action == ACTION_CONVERT[6]:
                    # python list dword
                    data += "\x00" * 3
                    output = "["
                    output += ",".join("0x%08X" % u32(data[i:i+4]) for i in range(0, size, 4))
                    output += "]"
                    print output
                elif self.action == ACTION_CONVERT[7]:
                    # python list qword
                    data += "\x00" * 7
                    output = "["
                    output += ",".join("%#018X" % u64(data[i:i+8]) for i in range(0, size, 8))
                    output += "]"
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

            if op in ("ret", "retn", "jmp", "bl") or addr < function_head:
                return

            c = GetCommentEx(addr, 0)
            if c and c.lower() == "format":
                # Get last opnd
                op_index = 1 if "," in GetDisasm(addr) else 0
                break
            elif name.endswith(("snprintf_chk",)):
                if op in ("mov", "lea") and dst.endswith(("r8", "[esp+10h]")):
                    op_index = 1
                    break
            elif name.endswith(("sprintf_chk",)):
                if op in ("mov", "lea") and ( dst.endswith(("rcx", "[esp+0Ch]", "R3")) or
                                              dst.endswith("ecx") and bits == 64 ):
                    op_index = 1
                    break
            elif name.endswith(("snprintf", "fnprintf")):
                if op in ("mov", "lea") and ( dst.endswith(("rdx", "[esp+8]", "R2")) or
                                              dst.endswith("edx") and bits == 64 ):
                    op_index = 1
                    break
            elif name.endswith(("sprintf", "fprintf", "dprintf", "printf_chk")):
                if op in ("mov", "lea") and ( dst.endswith(("rsi", "[esp+4]", "R1")) or
                                              dst.endswith("esi") and bits == 64 ):
                    op_index = 1
                    break
            elif name.endswith("printf"):
                if op in ("mov", "lea") and ( dst.endswith(("rdi", "[esp]", "R0")) or
                                              dst.endswith("edi") and bits == 64 ):
                    op_index = 1
                    break

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
            vdui = idaapi.get_tform_vdui(ctx.form)
            self.remove_rettype(vdui)
            vdui.refresh_ctext()
        elif self.action == ACTION_HX_COPYEA:
            vdui = idaapi.get_tform_vdui(ctx.form)
            ea = vdui.item.get_ea()
            if ea != idaapi.BADADDR:
                copy_to_clip("0x%X" % ea)
                print "Address 0x%X has been copied to clipboard" % ea
        elif self.action == ACTION_HX_COPYNAME:
            name = idaapi.get_highlighted_identifier()
            if name:
                copy_to_clip(name)
                print "%s has been copied to clipboard" % name
        else:
            return 0

        return 1

    def update(self, ctx):
        vdui = idaapi.get_tform_vdui(ctx.form)
        if vdui:
            return idaapi.AST_ENABLE_FOR_FORM
        else:
            return idaapi.AST_DISABLE_FOR_FORM

    @staticmethod
    def remove_rettype(vu):
        if vu.item.citype == idaapi.VDI_FUNC:
            # current function
            ea = vu.cfunc.entry_ea
            old_func_type = idaapi.tinfo_t()
            if not vu.cfunc.get_func_type(old_func_type):
                return False

        elif vu.item.citype == idaapi.VDI_EXPR and vu.item.e and vu.item.e.type.is_funcptr():
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
                return True

            # Create new function info with void rettype
            new_ret_type = idaapi.tinfo_t()
            new_ret_type.create_simple_type(idaapi.BT_VOID)
            fi.rettype = new_ret_type

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
                for action in ACTION_CONVERT:
                    idaapi.attach_action_to_popup(form, popup, action, "Convert/")

        if form_type == idaapi.BWN_DISASM and arch in (idaapi.PLFM_386, idaapi.PLFM_ARM):
            idaapi.attach_action_to_popup(form, popup, ACTION_SCANVUL, None)

class IDB_Hook(idaapi.IDB_Hooks):
    def __init__(self):
        idaapi.IDB_Hooks.__init__(self)

    def cmt_changed(self, ea, repeatable):
        if is_cgc:
            # fix cgc syscall comment
            cmt = GetCommentEx(ea, 0)
            if cmt and "LINUX - " in cmt:
                if cgc_syscall_map.has_key(cmt):
                    print "[+] 0x%X: Fix CGC syscall comment: %s" % (ea, GetCommentEx(ea, 0))
                    MakeComm(ea, cgc_syscall_map[cmt])
        return 0

class IDP_Hook(idaapi.IDP_Hooks):
    def __init__(self):
        idaapi.IDP_Hooks.__init__(self)

    def renamed(self, ea, new_name, local_name):
        if is_cgc:
            # fix cgc syscall type
            if cgc_syscall_type_map.has_key(new_name):
                SetType(ea, cgc_syscall_type_map[new_name])
                print "[+] 0x%X: Fix CGC syscall type: %s" % (ea, new_name)

def hexrays_callback(event, *args):
    if event == idaapi.hxe_populating_popup:
        form, phandle, vu = args
        if ( vu.item.citype == idaapi.VDI_FUNC ) or ( vu.item.citype == idaapi.VDI_EXPR and vu.item.e and vu.item.e.type.is_funcptr() ):
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
        global is_cgc

        arch = idaapi.ph_get_id()
        info = idaapi.get_inf_structure()
        if info.is_64bit():
            bits = 64
        elif info.is_32bit():
            bits = 32
        else:
            bits = 16

        is_cgc = "CGC" in idaapi.get_file_type_name()

        print "LazyIDA (Python Version) (v1.0.0.1) plugin has been loaded."

        # Register menu actions
        menu_actions = (
            idaapi.action_desc_t(ACTION_CONVERT[0], "Convert to string", menu_action_handler_t(ACTION_CONVERT[0]), None, None, 80),
            idaapi.action_desc_t(ACTION_CONVERT[1], "Convert to hex string", menu_action_handler_t(ACTION_CONVERT[1]), None, None, 8),
            idaapi.action_desc_t(ACTION_CONVERT[2], "Convert to C/C++ array (BYTE)", menu_action_handler_t(ACTION_CONVERT[2]), None, None, 38),
            idaapi.action_desc_t(ACTION_CONVERT[3], "Convert to C/C++ array (DWORD)", menu_action_handler_t(ACTION_CONVERT[3]), None, None, 38),
            idaapi.action_desc_t(ACTION_CONVERT[4], "Convert to C/C++ array (QWORD)", menu_action_handler_t(ACTION_CONVERT[4]), None, None, 38),
            idaapi.action_desc_t(ACTION_CONVERT[5], "Convert to python list (BYTE)", menu_action_handler_t(ACTION_CONVERT[5]), None, None, 201),
            idaapi.action_desc_t(ACTION_CONVERT[6], "Convert to python list (DWORD)", menu_action_handler_t(ACTION_CONVERT[6]), None, None, 201),
            idaapi.action_desc_t(ACTION_CONVERT[7], "Convert to python list (QWORD)", menu_action_handler_t(ACTION_CONVERT[7]), None, None, 201),
            idaapi.action_desc_t(ACTION_XORDATA, "Get xored data", menu_action_handler_t(ACTION_XORDATA), None, None, 9),
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

        # Add idb hook
        self.idb_hook = IDB_Hook()
        self.idb_hook.hook()

        # Add idp hook
        self.idp_hook = IDP_Hook()
        self.idp_hook.hook()

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

            idaapi.install_hexrays_callback(hexrays_callback)
            self.hexrays_inited = True

        # Auto apply libcgc signature
        if is_cgc and os.path.exists(idaapi.get_sig_filename("libcgc.sig")):
            if "libcgc.sig" not in [idaapi.get_idasgn_desc(i)[0] for i in range(idaapi.get_idasgn_qty())]:
                idaapi.plan_to_apply_idasgn("libcgc.sig")

        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        pass

    def term(self):
        if self.ui_hook:
            self.ui_hook.unhook()
        if self.idb_hook:
            self.idb_hook.unhook()
        if self.idp_hook:
            self.idp_hook.unhook()

        # Unregister actions
        for action in self.registered_actions:
            idaapi.unregister_action(action)

        if self.hexrays_inited:
            # Unregister hexrays actions
            for action in self.registered_hx_actions:
                idaapi.unregister_action(action)

            idaapi.remove_hexrays_callback(hexrays_callback)
            idaapi.term_hexrays_plugin()

def PLUGIN_ENTRY():
    return LazyIDA_t()
