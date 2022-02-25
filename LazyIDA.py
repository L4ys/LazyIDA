from __future__ import division
from __future__ import print_function
from struct import unpack
import idaapi
import idautils
import idc

from PyQt5.Qt import QApplication

ACTION_CONVERT = ["lazyida:convert%d" % i for i in range(10)]
ACTION_SCANVUL = "lazyida:scanvul"
ACTION_COPYEA = "lazyida:copyea"
ACTION_GOTOCLIP = "lazyida:gotoclip"
ACTION_XORDATA = "lazyida:xordata"
ACTION_FILLNOP = "lazyida:fillnop"

ACTION_HX_REMOVERETTYPE = "lazyida:hx_removerettype"
ACTION_HX_COPYEA = "lazyida:hx_copyea"
ACTION_HX_COPYNAME = "lazyida:hx_copyname"
ACTION_HX_GOTOCLIP = "lazyida:hx_gotoclip"

u16 = lambda x: unpack("<H", x)[0]
u32 = lambda x: unpack("<I", x)[0]
u64 = lambda x: unpack("<Q", x)[0]

ARCH = 0
BITS = 0

def copy_to_clip(data):
    QApplication.clipboard().setText(data)

def clip_text():
    return QApplication.clipboard().text()

def parse_location(loc):
    try:
        loc = int(loc, 16)
    except ValueError:
        try:
            loc = idc.get_name_ea_simple(loc.encode().strip())
        except:
            return idaapi.BADADDR
    return loc

class VulnChoose(idaapi.Choose):
    """
    Chooser class to display result of format string vuln scan
    """
    def __init__(self, title, items, icon, embedded=False):
        idaapi.Choose.__init__(self, title, [["Address", 20], ["Function", 30], ["Format", 30]], embedded=embedded)
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
        idc.jumpto(int(self.items[n][0], 16))

class hotkey_action_handler_t(idaapi.action_handler_t):
    """
    Action handler for hotkey actions
    """
    def __init__(self, action):
        idaapi.action_handler_t.__init__(self)
        self.action = action

    def activate(self, ctx):
        if self.action == ACTION_COPYEA:
            ea = idc.get_screen_ea()
            if ea != idaapi.BADADDR:
                copy_to_clip("0x%X" % ea)
                print("Address 0x%X has been copied to clipboard" % ea)
        elif self.action == ACTION_GOTOCLIP:
            loc = parse_location(clip_text())
            if loc != idaapi.BADADDR:
                print("Goto location 0x%x" % loc)
                idc.jumpto(loc)
        return 1

    def update(self, ctx):
        if idaapi.IDA_SDK_VERSION >= 770:
            target_attr = "widget_type"
        else:
            target_attr = "form_type"
        if ctx.__getattribute__(target_attr) in (idaapi.BWN_DISASM, idaapi.BWN_DUMP):
            return idaapi.AST_ENABLE_FOR_WIDGET
        else:
            return idaapi.AST_DISABLE_FOR_WIDGET

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
            t0, t1, view = idaapi.twinpos_t(), idaapi.twinpos_t(), idaapi.get_current_viewer()
            if idaapi.read_selection(view, t0, t1):
                start, end = t0.place(view).toea(), t1.place(view).toea()
                size = end - start + 1
            elif idc.get_item_size(idc.get_screen_ea()) > 1:
                start = idc.get_screen_ea()
                size = idc.get_item_size(start)
                end = start + size
            else:
                return False

            data = idc.get_bytes(start, size)
            if isinstance(data, str):  # python2 compatibility
                data = bytearray(data)
            name = idc.get_name(start, idc.GN_VISIBLE)
            if not name:
                name = "data"
            if data:
                print("\n[+] Dump 0x%X - 0x%X (%u bytes) :" % (start, end, size))
                if self.action == ACTION_CONVERT[0]:
                    # escaped string
                    output = '"%s"' % "".join("\\x%02X" % b for b in data)
                elif self.action == ACTION_CONVERT[1]:
                    # hex string
                    output = "".join("%02X" % b for b in data)
                elif self.action == ACTION_CONVERT[2]:
                    # C array
                    output = "unsigned char %s[%d] = {" % (name, size)
                    for i in range(size):
                        if i % 16 == 0:
                            output += "\n    "
                        output += "0x%02X, " % data[i]
                    output = output[:-2] + "\n};"
                elif self.action == ACTION_CONVERT[3]:
                    # C array word
                    data += b"\x00"
                    array_size = (size + 1) // 2
                    output = "unsigned short %s[%d] = {" % (name, array_size)
                    for i in range(0, size, 2):
                        if i % 16 == 0:
                            output += "\n    "
                        output += "0x%04X, " % u16(data[i:i+2])
                    output = output[:-2] + "\n};"
                elif self.action == ACTION_CONVERT[4]:
                    # C array dword
                    data += b"\x00" * 3
                    array_size = (size + 3) // 4
                    output = "unsigned int %s[%d] = {" % (name, array_size)
                    for i in range(0, size, 4):
                        if i % 32 == 0:
                            output += "\n    "
                        output += "0x%08X, " % u32(data[i:i+4])
                    output = output[:-2] + "\n};"
                elif self.action == ACTION_CONVERT[5]:
                    # C array qword
                    data += b"\x00" * 7
                    array_size = (size + 7) // 8
                    output = "unsigned long %s[%d] = {" % (name, array_size)
                    for i in range(0, size, 8):
                        if i % 32 == 0:
                            output += "\n    "
                        output += "0x%016X, " % u64(data[i:i+8])
                    output = output[:-2] + "\n};"
                elif self.action == ACTION_CONVERT[6]:
                    # python list
                    output = "[%s]" % ", ".join("0x%02X" % b for b in data)
                elif self.action == ACTION_CONVERT[7]:
                    # python list word
                    data += b"\x00"
                    output = "[%s]" % ", ".join("0x%04X" % u16(data[i:i+2]) for i in range(0, size, 2))
                elif self.action == ACTION_CONVERT[8]:
                    # python list dword
                    data += b"\x00" * 3
                    output = "[%s]" % ", ".join("0x%08X" % u32(data[i:i+4]) for i in range(0, size, 4))
                elif self.action == ACTION_CONVERT[9]:
                    # python list qword
                    data += b"\x00" * 7
                    output = "[%s]" %  ", ".join("%#018X" % u64(data[i:i+8]) for i in range(0, size, 8)).replace("0X", "0x")
                copy_to_clip(output)
                print(output)
        elif self.action == ACTION_XORDATA:
            t0, t1, view = idaapi.twinpos_t(), idaapi.twinpos_t(), idaapi.get_current_viewer()
            if idaapi.read_selection(view, t0, t1):
                start, end = t0.place(view).toea(), t1.place(view).toea()
            else:
                if idc.get_item_size(idc.get_screen_ea()) > 1:
                    start = idc.get_screen_ea()
                    end = start + idc.get_item_size(start)
                else:
                    return False

            data = idc.get_bytes(start, end - start)
            if isinstance(data, str):  # python2 compatibility
                data = bytearray(data)
            x = idaapi.ask_long(0, "Xor with...")
            if x:
                x &= 0xFF
                print("\n[+] Xor 0x%X - 0x%X (%u bytes) with 0x%02X:" % (start, end, end - start, x))
                print(repr("".join(chr(b ^ x) for b in data)))
        elif self.action == ACTION_FILLNOP:
            t0, t1, view = idaapi.twinpos_t(), idaapi.twinpos_t(), idaapi.get_current_viewer()
            if idaapi.read_selection(view, t0, t1):
                start, end = t0.place(view).toea(), t1.place(view).toea()
                idaapi.patch_bytes(start, b"\x90" * (end - start))
                print("\n[+] Fill 0x%X - 0x%X (%u bytes) with NOPs" % (start, end, end - start))
        elif self.action == ACTION_SCANVUL:
            print("\n[+] Finding Format String Vulnerability...")
            found = []
            for addr in idautils.Functions():
                name = idc.get_func_name(addr)
                if "printf" in name and "v" not in name and idc.get_segm_name(addr) in (".text", ".plt", ".idata", ".plt.got"):
                    xrefs = idautils.CodeRefsTo(addr, False)
                    for xref in xrefs:
                        vul = self.check_fmt_function(name, xref)
                        if vul:
                            found.append(vul)
            if found:
                print("[!] Done! %d possible vulnerabilities found." % len(found))
                ch = VulnChoose("Vulnerability", found, None, False)
                ch.Show()
            else:
                print("[-] No format string vulnerabilities found.")
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
        function_head = idc.get_func_attr(addr, idc.FUNCATTR_START)

        while True:
            addr = idc.prev_head(addr)
            op = idc.print_insn_mnem(addr).lower()
            dst = idc.print_operand(addr, 0)

            if op in ("ret", "retn", "jmp", "b") or addr < function_head:
                return

            c = idc.get_cmt(addr, 0)
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
        op_index = idc.generate_disasm_line(addr, 0).count(",")
        op_type = idc.get_operand_type(addr, op_index)
        opnd = idc.print_operand(addr, op_index)

        if op_type == idc.o_reg:
            # format is in register, try to track back and get the source
            _addr = addr
            while True:
                _addr = idc.prev_head(_addr)
                _op = idc.print_insn_mnem(_addr).lower()
                if _op in ("ret", "retn", "jmp", "b") or _addr < function_head:
                    break
                elif _op in ("mov", "lea", "ldr") and idc.print_operand(_addr, 0) == opnd:
                    op_type = idc.get_operand_type(_addr, 1)
                    opnd = idc.print_operand(_addr, 1)
                    addr = _addr
                    break

        if op_type == idc.o_imm or op_type == idc.o_mem:
            # format is a memory address, check if it's in writable segment
            op_addr = idc.get_operand_value(addr, op_index)
            seg = idaapi.getseg(op_addr)
            if seg:
                if not seg.perm & idaapi.SEGPERM_WRITE:
                    # format is in read-only segment
                    return

        print("0x%X: Possible Vulnerability: %s, format = %s" % (addr, name, opnd))
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
            vdui = idaapi.get_widget_vdui(ctx.widget)
            self.remove_rettype(vdui)
            vdui.refresh_ctext()
        elif self.action == ACTION_HX_COPYEA:
            ea = idaapi.get_screen_ea()
            if ea != idaapi.BADADDR:
                copy_to_clip("0x%X" % ea)
                print("Address 0x%X has been copied to clipboard" % ea)
        elif self.action == ACTION_HX_COPYNAME:
            name = idaapi.get_highlight(idaapi.get_current_viewer())[0]
            if name:
                copy_to_clip(name)
                print("%s has been copied to clipboard" % name)
        elif self.action == ACTION_HX_GOTOCLIP:
            loc = parse_location(clip_text())
            print("Goto location 0x%x" % loc)
            idc.jumpto(loc)
        else:
            return 0

        return 1

    def update(self, ctx):
        vdui = idaapi.get_widget_vdui(ctx.widget)
        return idaapi.AST_ENABLE_FOR_WIDGET if vdui else idaapi.AST_DISABLE_FOR_WIDGET

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
            if idaapi.apply_tinfo(ea, new_func_type, idaapi.TINFO_DEFINITE):
                return vu.refresh_view(True)

        return False

class UI_Hook(idaapi.UI_Hooks):
    def __init__(self):
        idaapi.UI_Hooks.__init__(self)

    def finish_populating_widget_popup(self, form, popup):
        form_type = idaapi.get_widget_type(form)

        if form_type == idaapi.BWN_DISASM or form_type == idaapi.BWN_DUMP:
            t0, t1, view = idaapi.twinpos_t(), idaapi.twinpos_t(), idaapi.get_current_viewer()
            if idaapi.read_selection(view, t0, t1) or idc.get_item_size(idc.get_screen_ea()) > 1:
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
                    addr = idc.get_name_ea_simple(name)
                    if addr == idaapi.BADADDR:
                        # try class::function
                        e = vu.item.e
                        while e.x:
                            e = e.x
                        addr = idc.get_name_ea_simple("%s::%s" % (str(e.type).split()[0], name))

                    if addr != idaapi.BADADDR:
                        idc.jumpto(addr)
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

        print("LazyIDA (v1.0.0.3) plugin has been loaded.")

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
            idaapi.action_desc_t(ACTION_GOTOCLIP, "Goto clip EA", hotkey_action_handler_t(ACTION_GOTOCLIP), "Shift-G", "Goto clipboard EA", 0),
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
                idaapi.action_desc_t(ACTION_HX_GOTOCLIP, "Goto clipboard ea", hexrays_action_handler_t(ACTION_HX_GOTOCLIP), "Shift-G"),
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
        if hasattr(self, "ui_hook"):
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

