from mythic_payloadtype_container.MythicCommandBase import *
import json


class Keylog_no_XArguments(TaskArguments):
    def __init__(self, command_line):
        super().__init__(command_line)
        self.args = {}

    async def parse_arguments(self):
        pass


class Keylog_no_XCommand(CommandBase):
    cmd = "keylog_no_X"
    needs_admin = False
    help_cmd = "keylog"
    description = "Keylog without X, needs to have root privileges"
    version = 1
    supported_ui_features = []
    author = "@Kayn93"
    argument_class = Keylog_no_XArguments
    attackmapping = ["T1056"]

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        return task

    async def process_response(self, response: AgentResponse):
        pass
