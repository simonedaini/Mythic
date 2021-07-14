from mythic_payloadtype_container.MythicCommandBase import *
from mythic_payloadtype_container.MythicRPC import *
import base64
import os
import json


class CodeArguments(TaskArguments):
    def __init__(self, command_line):
        super().__init__(command_line)
        self.args = {}

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise ValueError("Need to specify commands to load")
        pass
        params = self.command_line.split(";;;")
        self.add_arg("code", params[0])
        self.add_arg("param", params[1])
        self.add_arg("parallel_id", params[2])


class CodeCommand(CommandBase):
    cmd = "code"
    needs_admin = False
    help_cmd = "auxiliary function to run python code in parallel"
    description = "This runs the code passed as argument"
    version = 1
    author = "@Kayn93"
    parameters = []
    attackmapping = ["T1030", "T1129"]
    argument_class = CodeArguments

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        return task

    async def process_response(self, response: AgentResponse):
        pass
