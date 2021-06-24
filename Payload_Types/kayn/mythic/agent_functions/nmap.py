from mythic_payloadtype_container.MythicCommandBase import *
import json


class NmapArguments(TaskArguments):
    def __init__(self, command_line):
        super().__init__(command_line)
        self.args = {}

    async def parse_arguments(self):
        pass


class NmapCommand(CommandBase):
    cmd = "nmap"
    needs_admin = False
    help_cmd = "nmap"
    description = "returns SSH credentials and triggers the execution of Nmap over through the tunnel"
    version = 1
    supported_ui_features = [""]
    author = "@Kayn93"
    argument_class = NmapArguments
    attackmapping = []

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        return task

    async def process_response(self, response: AgentResponse):
        pass
