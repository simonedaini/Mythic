from mythic_payloadtype_container.MythicCommandBase import *
import json
from mythic_payloadtype_container.MythicRPC import *

class ShellArguments(TaskArguments):
    def __init__(self, command_line):
        super().__init__(command_line)
        self.args = {}

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise ValueError("Need to specify command to run")
        pass


class ShellCommand(CommandBase):
    cmd = "shell"
    needs_admin = False
    help_cmd = "shell cmd"
    description = "Run cmd into a shell and return the result"
    version = 1
    supported_ui_features = [""]
    author = "@Kayn93"
    parameters = []
    attackmapping = []
    argument_class = ShellArguments

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        return task

    async def process_response(self, response: AgentResponse):
        pass