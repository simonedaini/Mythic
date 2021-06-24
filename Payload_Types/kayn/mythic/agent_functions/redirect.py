from mythic_payloadtype_container.MythicCommandBase import *
import json


class RedirectArguments(TaskArguments):
    def __init__(self, command_line):
        super().__init__(command_line)
        self.args = {}

    async def parse_arguments(self):
        pass


class RedirectCommand(CommandBase):
    cmd = "redirect"
    needs_admin = False
    help_cmd = "nmap"
    description = "Change address:port of the server that the agent communicates with"
    version = 1
    supported_ui_features = [""]
    author = "@Kayn93"
    argument_class = RedirectArguments
    attackmapping = []

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        return task

    async def process_response(self, response: AgentResponse):
        pass
