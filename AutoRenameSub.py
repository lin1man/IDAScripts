import idaapi
import ida_kernwin
import re
from threading import Timer

class AutoRenameSubHandler(idaapi.View_Hooks):
    def __init__(self):
        super().__init__()
        self.pattern = re.compile(r'^sub_[0-9A-F]+$', re.IGNORECASE)
        self.timer = None
        self.enabled = self.load_config()
        self.register_actions()

    def view_activated(self, view):
        if not self.enabled:
            return
        if self.timer and self.timer.is_alive():
            self.timer.cancel()
        self.timer = Timer(0.1, self.process_rename_t)
        self.timer.start()

    def process_rename_t(self):
        idaapi.execute_sync(self.process_rename, idaapi.MFF_WRITE)

    def process_rename(self):
        ea = idaapi.get_screen_ea()
        func = idaapi.get_func(ea)
        if func:
            func_ea = func.start_ea
            func_name = idaapi.get_func_name(func_ea)

            if self.pattern.match(func_name):
                new_name = "unsub_" + func_name[4:]
                idaapi.set_name(func_ea, new_name, idaapi.SN_CHECK)
                print(f"Auto-renamed {func_name} to {new_name} at {hex(func_ea)}")

    def load_config(self):
        return bool(idaapi.netnode("$ AutoRenameSubEnable").altval(0))

    def save_config(self, state):
        idaapi.netnode("$ AutoRenameSubEnable").altset(0, int(state))

    def register_actions(self):
        action_desc = ida_kernwin.action_desc_t(
            "AutoRenameSub_Enable",
            ("Disable" if self.enabled else "Enable") + " AutoRenameSub",
            AutoRenameSubActionHandler(self),
            None,
            "Enable/Disable AutoRenameSub"
        )
        ida_kernwin.register_action(action_desc)
        ida_kernwin.attach_action_to_menu("Edit/", "AutoRenameSub_Enable", ida_kernwin.SETMENU_APP)

    def unregister_actions(self):
        ida_kernwin.unregister_action("AutoRenameSub_Enable")

class AutoRenameSubPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_HIDE
    comment = "Auto rename sub_xxxx functions"
    help = "Auto rename sub_xxxx to unsub_xxxx when viewed"
    wanted_name = "AutoRenameSub"

    def init(self):
        self.hooks = AutoRenameSubHandler()
        self.hooks.hook()
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        pass

    def term(self):
        self.hooks.unregister_actions()
        self.hooks.unhook()

class AutoRenameSubActionHandler(ida_kernwin.action_handler_t):
    def __init__(self, plugin):
        ida_kernwin.action_handler_t.__init__(self)
        self.plugin = plugin

    def activate(self, ctx):
        enabled = not self.plugin.enabled
        self.plugin.enabled = enabled
        desc = ("Disable" if enabled else "Enable") + " AutoRenameSub"
        ida_kernwin.update_action_label("AutoRenameSub_Enable", desc)
        self.plugin.save_config(enabled)
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

def PLUGIN_ENTRY():
    return AutoRenameSubPlugin()