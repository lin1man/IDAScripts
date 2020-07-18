# === Import

import collections

# IDA Python SDK
from idaapi import *
from idc import *
from idautils import *

WUTILS_PLUGIN_NAME        = "wUtils"
WUTILS_PLUGIN_MENU_NAME   = "wUtils"

# === Helpers

class WUTILS_HELPERS:
    # Menu

    MenuItem = collections.namedtuple("MenuItem", ["action", "handler", "title", "tooltip", "shortcut", "popup"])

    class IdaMenuActionHandler(action_handler_t):
        def __init__(self, handler, action):
            action_handler_t.__init__(self)
            self.action_handler = handler
            self.action_type = action

        def activate(self, ctx):
            if ctx.form_type == BWN_DISASM:
                self.action_handler.handle_menu_action(self.action_type)
            return 1

        # This action is always available.
        def update(self, ctx):
            return AST_ENABLE_ALWAYS


def put_unconditional_branch(source, destination):
    offset = (destination - source - 4) >> 1
    if offset > 2097151 or offset < -2097152:   # 0x200000 2MB
        raise RuntimeError("Invalid offset")
    if offset > 1023 or offset < -1024:
        instruction1 = 0xf000 | ((offset >> 11) & 0x7ff)
        instruction2 = 0xb800 | (offset & 0x7ff)
        patch_word(source, instruction1)
        patch_word(source + 2, instruction2)
    else:
        instruction = 0xe000 | (offset & 0x7ff)
        patch_word(source, instruction)

def str2cond(strcond):
    strcond = strcond.lower()
    if strcond == "eq":     # Equal                     Equal                           Z == 1
        return 0x00 # 0000
    elif strcond == "ne":   # Not Equal                 Not equal,or unordered          Z == 0
        return 0x01 # 0001
    elif strcond == "cs":   # Carray set                Greater than,equal,or unordered C == 1
        return 0x02 # 0001
    elif strcond == "cc":   # Carray clear              Less than                       C == 0
        return 0x03 # 0001
    elif strcond == "mi":   # Minus,negativ             Less than                       N == 1
        return 0x04 # 0001
    elif strcond == "pl":   # Plus,positive or zero     Greater than,equal,or unordered N == 0
        return 0x05 # 0001
    elif strcond == "vs":   # Overflow                  Unordered                       V == 1
        return 0x06 # 0001
    elif strcond == "vc":   # No overflow               Not unordered                   V == 0
        return 0x07 # 0001
    elif strcond == "hi":   # Unsigned higher           Greater than,or unordered       C == 1 and Z == 0
        return 0x08 # 0001
    elif strcond == "ls":   # Unsigned lower or same    Less than or equal              C == 0 or Z == 1
        return 0x09 # 0001
    elif strcond == "ge":   # Signed greater than or equal Greater than or equal        N == V
        return 0x0a # 0001
    elif strcond == "lt":   # Signed less than          Less than, or unordered         N != V
        return 0x0b # 0001
    elif strcond == "gt":   # Signed greater than       Greater than                    Z == 0 and N == V
        return 0x0c # 0001
    elif strcond == "le":   # Signed less than or equal Less than,equal,or unordered    Z == 1 or N != V
        return 0x0d # 0001
    elif strcond == "al":   # Always(unconditional)     Always(unconditional)           Any
        return 0x0e # 0001
    else:
        raise RuntimeError("Invalid cond")
    # Unordered means at least one NaN operand
    # HS (unsigned higher or sam) is a synonym for CS
    # LO (unsigned lower) is a synonym for CC
    # AL is an optional mnemonic extension for always,except in IT instructions


def put_conditional_branch_t3(source, destination, cond):
    offset = (destination - source - 4) >> 1
    if offset > 262144 or offset < -262145:     # 0x400000 4mb
        raise RuntimeError("Invalid offset")
    instruction1 = 0xf000 | ((offset >> 11) & 0x3f)   #1111 0S
    instruction1 = instruction1 | ((cond & 0x0f) << 6) | (((offset >> 19) & 0x01) << 10)
    instruction2 = 0x8000 | (offset & 0x7ff) | (((offset >> 17) & 0x1) << 13) | (((offset >> 18) & 0x1) << 11)
    patch_word(source, instruction1)
    patch_word(source + 2, instruction2)


def put_bl_call_branch(source, destination):
    offset = (destination - source - 4 - 2) >> 1        #4 for pc, 2 for PUSH {LR}
    if offset > 2097151 or offset < -2097152:   # 0x200000 2MB
        raise RuntimeError("Invalid offset")
    instruction1 = 0xb500                               #PUSH {LR}
    instruction2 = 0xf000 | ((offset >> 11) & 0x7ff)    #BL imm10
    instruction3 = 0xf800 | (offset & 0x7ff)            #BL imm11   imm32=signExtend(s:0:0:imm10:imm11:'0',32)
    instruction4 = 0xbd00                               #PUSH {PC}
    patch_word(source, instruction1)
    patch_word(source+2, instruction2)
    patch_word(source+4, instruction3)
    patch_word(source+6, instruction4)


def wutils_log(entry):
    msg("[" + WUTILS_PLUGIN_NAME + "]: " + entry + "\n")

class dumpMemoryRangeDialog(Form):
    def __init__(self):
        Form.__init__(self, r"""STARTITEM {id:mem_size}
BUTTON YES* Confirm
BUTTON CANCEL Cancel
Dump Memory Range
Specify start address and size of memory range.
<##DumpPath\::{dump_path}>
<##Address \::{mem_addr}> <##Size\::{mem_size}>
""", {
        'dump_path': Form.StringInput(swidth=41),
        'mem_addr': Form.NumericInput(swidth=20, tp=Form.FT_HEX),
        'mem_size': Form.NumericInput(swidth=10, tp=Form.FT_DEC)
        })

class uncondictionalBranchDialog(Form):
    def __init__(self):
        Form.__init__(self, r"""STARTITEM {id:branch_addr}
BUTTON YES* Confirm
BUTTON CANCEL Cancel
Unconditional branch
Specify address of branch.
<##Source  \::{source_addr}>
<##Address \::{branch_addr}>
""", {
        'source_addr': Form.NumericInput(swidth=20, tp=Form.FT_HEX),
        'branch_addr': Form.NumericInput(swidth=20, tp=Form.FT_HEX)
        })

class condictionalBranchDialog(Form):
    def __init__(self):
        Form.__init__(self, r"""STARTITEM {id:branch_addr}
BUTTON YES* Confirm
BUTTON CANCEL Cancel
Conditional branch
Specify address of branch and cond.
Cond can be:eq,ne,cs,cc,mi,pl,vs,vc,hi,ls,ge,lt,gt,le,al
<##Source  \::{source_addr}>
<##Cond    \::{cond}>
<##Address \::{branch_addr}>
""", {
        'source_addr': Form.NumericInput(swidth=20, tp=Form.FT_HEX),
        'cond': Form.StringInput(swidth=20),
        'branch_addr': Form.NumericInput(swidth=20, tp=Form.FT_HEX)
        })

class callFunctionDialog(Form):
    def __init__(self):
        Form.__init__(self, r"""STARTITEM {id:func_addr}
BUTTON YES* Confirm
BUTTON CANCEL Cancel
Call function
Specify address of function.
<##Source  \::{source_addr}>
<##Address \::{func_addr}>
""", {
        'source_addr': Form.NumericInput(swidth=20, tp=Form.FT_HEX),
        'func_addr': Form.NumericInput(swidth=20, tp=Form.FT_HEX)
        })

class recoverPatchDialog(Form):
    def __init__(self):
        Form.__init__(self, r"""STARTITEM {id:patch_size}
BUTTON YES* Confirm
BUTTON CANCEL Cancel
Recover patch
Specify address of recover.
<##Address \::{patch_addr}> <##Size\::{patch_size}>
""", {
        'patch_addr': Form.NumericInput(swidth=20, tp=Form.FT_HEX),
        'patch_size': Form.NumericInput(swidth=10, tp=Form.FT_DEC)
        })

class loadScriptFileDialog(Form):
    def __init__(self):
        Form.__init__(self, r"""STARTITEM {id:file_name}
BUTTON YES* Load
BUTTON CANCEL Cancel
Load Script File
{form_change_cb}
<#Select file to load#File\::{file_name}>

""", {
        'file_name': Form.FileInput(swidth=50, open=True),
        'form_change_cb': Form.FormChangeCb(self.OnFormChange)
        })

    def OnFormChange(self, fid):
        if fid == self.file_name.id:
            filepath = self.GetControlValue(self.file_name)
            print (filepath)
        return 1


# === wUtilsPlugin

class wUtilsPlugin(plugin_t, UI_Hooks):
    popup_menu_hook = None
    flags = PLUGIN_HIDE
    comment = ""
    help = "Tiny cute emulator"
    wanted_name = WUTILS_PLUGIN_MENU_NAME
    wanted_hotkey = ""

    # --- PLUGIN LIFECYCLE

    def init(self):
        super(wUtilsPlugin, self).__init__()
        self.hook_ui_actions()
        self.lastLoadScript = ""
        wutils_log("Init plugin")
        return PLUGIN_KEEP

    def run(self, arg):
        wutils_log("Run plugin with (%d)" % arg)

    def run(self, arg = 0):
        wutils_log("Run plugin")
        self.register_menu_actions()
        self.attach_main_menu_actions()

    def term(self): # asynchronous unload (external, UI_Hook::term)
        self.unhook_ui_actions()
        self.detach_main_menu_actions()
        self.unregister_menu_actions()
        wutils_log("Unload plugin")

    def unload_plugin(self): # synchronous unload (internal, Main Menu)
        self.unregister_menu_actions()
        self.detach_main_menu_actions()
        self.unhook_ui_actions()

    def do_nothing(self):
        pass

    def ready_to_run(self):
        wutils_log("UI ready. Run plugin")
        self.register_menu_actions()
        self.attach_main_menu_actions()

    # --- MAIN MENU

    MENU_ITEMS = []

    def register_new_action(self, act_name, act_text, act_handler, shortcut, tooltip, icon):
        new_action = action_desc_t(
            act_name,       # The action name. This acts like an ID and must be unique
            act_text,       # The action text.
            act_handler,    # The action handler.
            shortcut,       # Optional: the action shortcut
            tooltip,        # Optional: the action tooltip (available in menus/toolbar)
            icon)           # Optional: the action icon (shows when in menus/toolbars)
        register_action(new_action)

    def handle_menu_action(self, action):
        [x.handler() for x in self.MENU_ITEMS if x.action == action]

    def register_menu_actions(self):
        self.MENU_ITEMS.append(WUTILS_HELPERS.MenuItem(WUTILS_PLUGIN_NAME + ":dump",            self.dump_memory,           "Dump range",           "Dump memory range",        "SHIFT+CTRL+ALT+D",     True    ))
        self.MENU_ITEMS.append(WUTILS_HELPERS.MenuItem(WUTILS_PLUGIN_NAME + ":branch",          self.unconditonal_branch,   "UnconditionalBranch",  "Unconditonal branch",      "SHIFT+CTRL+ALT+B",     True    ))
        self.MENU_ITEMS.append(WUTILS_HELPERS.MenuItem(WUTILS_PLUGIN_NAME + ":condbranch",      self.conditonal_branch,     "ConditionalBranch",    "Conditonal branch",        "SHIFT+CTRL+B",         True    ))
        self.MENU_ITEMS.append(WUTILS_HELPERS.MenuItem(WUTILS_PLUGIN_NAME + ":call",            self.call_function,         "Call function",        "Call function",            "SHIFT+CTRL+ALT+C",     True    ))
        self.MENU_ITEMS.append(WUTILS_HELPERS.MenuItem("-",                                     self.do_nothing,            "",                     None,                       None,                   True    ))
        self.MENU_ITEMS.append(WUTILS_HELPERS.MenuItem(WUTILS_PLUGIN_NAME + ":repatch",         self.recover_patch,         "Recover patch",        "Recover patch",            "SHIFT+CTRL+ALT+R",     True    ))
        self.MENU_ITEMS.append(WUTILS_HELPERS.MenuItem(WUTILS_PLUGIN_NAME + ":deletefunc",      self.delete_func,           "Delete function",      None,                       "SHIFT+CTRL+D",         True    ))
        self.MENU_ITEMS.append(WUTILS_HELPERS.MenuItem("-",                                     self.do_nothing,            "",                     None,                       None,                   True    ))
        self.MENU_ITEMS.append(WUTILS_HELPERS.MenuItem(WUTILS_PLUGIN_NAME + ":loadscript",      self.load_script,           "Load script",          None,                       "SHIFT+CTRL+ALT+L",     True    ))
        self.MENU_ITEMS.append(WUTILS_HELPERS.MenuItem("-",                                     self.do_nothing,            "",                     None,                       None,                   False   ))
        self.MENU_ITEMS.append(WUTILS_HELPERS.MenuItem(WUTILS_PLUGIN_NAME + ":unload",          self.unload_plugin,         "Unload Plugin",        "Unload Plugin",            None,                   False   ))

        for item in self.MENU_ITEMS:
            if item.action == "-":
                continue
            self.register_new_action(item.action, item.title, WUTILS_HELPERS.IdaMenuActionHandler(self, item.action), item.shortcut, item.tooltip,  -1)

    def unregister_menu_actions(self):
        for item in self.MENU_ITEMS:
            if item.action == "-":
                continue
            unregister_action(item.action)

    def attach_main_menu_actions(self):
        for item in self.MENU_ITEMS:
            attach_action_to_menu("Edit/Plugins/" + WUTILS_PLUGIN_MENU_NAME + "/" + item.title, item.action, SETMENU_APP)

    def detach_main_menu_actions(self):
        for item in self.MENU_ITEMS:
            detach_action_from_menu("Edit/Plugins/" + WUTILS_PLUGIN_MENU_NAME + "/" + item.title, item.action)

    # --- POPUP MENU
    def hook_ui_actions(self):
        self.popup_menu_hook = self
        self.popup_menu_hook.hook()

    def unhook_ui_actions(self):
        if self.popup_menu_hook != None:
            self.popup_menu_hook.unhook()

    # IDA 7.x
    def finish_populating_widget_popup(self, widget, popup_handle):
        if get_widget_type(widget) == BWN_DISASM:
            for item in self.MENU_ITEMS:
                if item.popup:
                    attach_action_to_popup(widget, popup_handle, item.action, WUTILS_PLUGIN_MENU_NAME + "/")

    # IDA 6.x
    def finish_populating_tform_popup(self, form, popup_handle):
        if get_tform_type(form) == BWN_DISASM:
            for item in self.MENU_ITEMS:
                if item.popup:
                    attach_action_to_popup(form, popup_handle, item.action, WUTILS_PLUGIN_MENU_NAME + "/")

    def dump_memory(self, address=-1, size=16, dumppath='D:\\dump.bin'):
        ddlg = dumpMemoryRangeDialog()
        ddlg.Compile()
        if address == -1:
            address = here()
        ddlg.mem_addr.value = address
        ddlg.mem_size.value = size
        ddlg.dump_path.value = dumppath
        ok = ddlg.Execute()
        if ok == 1: #confirm
            mem_addr = ddlg.mem_addr.value
            mem_size = ddlg.mem_size.value
            dump_path = ddlg.dump_path.value
            with open(dump_path, "w") as f:
                bytes = get_bytes(mem_addr, mem_size)
                f.write(bytes)

    def unconditonal_branch(self, source=-1, address=-1):
        uBranchDlg = uncondictionalBranchDialog()
        uBranchDlg.Compile()
        if source == -1:
            source = here()
        if address == -1:
            address = here()
        uBranchDlg.source_addr.value = source
        uBranchDlg.branch_addr.value = address
        ok = uBranchDlg.Execute()
        if ok == 1:
            source = uBranchDlg.source_addr.value
            address = uBranchDlg.branch_addr.value
            print ("UnconditionBranch:", hex(source))
            put_unconditional_branch(source, address)

    def conditonal_branch(self, source=-1, cond="eq", address=-1):
        branchDlg = condictionalBranchDialog()
        branchDlg.Compile()
        if source == -1:
            source = here()
        if address == -1:
            address = here()
        branchDlg.source_addr.value = source
        branchDlg.cond.value = cond
        branchDlg.branch_addr.value = address
        ok = branchDlg.Execute()
        if ok == 1:
            source = branchDlg.source_addr.value
            strcond = branchDlg.cond.value
            address = branchDlg.branch_addr.value
            print ("ConditionBranch:%x b%s %x" % (source, cond, address))
            dcond = str2cond(strcond)
            put_conditional_branch_t3(source, address, dcond)

    def call_function(self, source=-1, address=-1):
        callFuncDlg = callFunctionDialog()
        callFuncDlg.Compile()
        if source == -1:
            source = here()
        if address == -1:
            address = here()
        callFuncDlg.source_addr.value = source
        callFuncDlg.func_addr.value = address
        ok = callFuncDlg.Execute()
        if ok == 1:
            source = callFuncDlg.source_addr.value
            address = callFuncDlg.func_addr.value
            print ("CallFunction:", hex(source))
            put_bl_call_branch(source, address)


    def recover_patch(self, address=-1, size=16):
        rePatchDlg = recoverPatchDialog()
        rePatchDlg.Compile()
        if address == -1:
            address = here()
        rePatchDlg.patch_addr.value = address
        rePatchDlg.patch_size.value = size
        ok = rePatchDlg.Execute()
        if ok == 1:
            address = rePatchDlg.patch_addr.value
            size = rePatchDlg.patch_size.value
            for i in range(size):
                patch_byte(address + i, get_original_byte(address + i))


    def load_script(self, scriptfile=""):
        loadScriptDlg = loadScriptFileDialog()
        loadScriptDlg.Compile()
        if scriptfile == "":
            scriptfile = self.lastLoadScript
        loadScriptDlg.file_name.value = scriptfile
        ok = loadScriptDlg.Execute()
        if ok == 1:
            self.lastLoadScript = loadScriptDlg.file_name.value
            module_name = os.path.basename(self.lastLoadScript)
            module_name = module_name.replace('.py', '')
            print ("Require module:", module_name)
            ida_idaapi.require(module_name)

    def delete_func(self):
        del_func(here())

def PLUGIN_ENTRY():
        return wUtilsPlugin()


if __name__ == '__main__':
    sys.path.append(os.path.dirname(__file__))
    uEmu = wUtilsPlugin()
    uEmu.init()
    uEmu.run()
