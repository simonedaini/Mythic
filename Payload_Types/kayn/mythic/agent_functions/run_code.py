from mythic_payloadtype_container.MythicCommandBase import *
from mythic_payloadtype_container.MythicRPC import *
import base64
import os
import json


class RunArguments(TaskArguments):
    def __init__(self, command_line):
        super().__init__(command_line)
        self.args = {}

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise ValueError("Need to specify commands to load")
        pass


class RunCommand(CommandBase):
    cmd = "run"
    needs_admin = False
    help_cmd = "run python code passed as argument"
    description = "This runs the code passed as argument"
    version = 1
    author = "@Kayn93"
    parameters = []
    attackmapping = ["T1030", "T1129"]
    argument_class = RunArguments

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        return task

    async def process_response(self, response: AgentResponse):
        pass
