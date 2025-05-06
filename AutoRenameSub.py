import idaapi
import idautils
import re
from threading import Timer

class AutoRenameSubHandler(idaapi.View_Hooks):
    def __init__(self):
        super().__init__()
        self.pattern = re.compile(r'^sub_[0-9A-F]+$', re.IGNORECASE)
        self.timer = None

    def view_activated(self, view):
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
        self.hooks.unhook()

def PLUGIN_ENTRY():
    return AutoRenameSubPlugin()