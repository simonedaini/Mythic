from mythic_payloadtype_container.MythicCommandBase import *
import json


class RunArguments(TaskArguments):
    def __init__(self, command_line):
        super().__init__(command_line)
        self.args = {}

    async def parse_arguments(self):
        pass


class NmapCommand(CommandBase):
    cmd = "run"
    needs_admin = False
    help_cmd = "run"
    description = "uploads a .py and executes it"
    version = 1
    supported_ui_features = [""]
    author = "@Kayn93"
    argument_class = RunArguments
    attackmapping = []

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        return task

    async def process_response(self, response: AgentResponse):
        pass
