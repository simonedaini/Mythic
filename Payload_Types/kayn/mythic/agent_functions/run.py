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
    help_cmd = "run example.py"
    description = "This uploads a .py onto the agent and runs it"
    version = 1
    author = "@Kayn93"
    parameters = []
    attackmapping = ["T1030", "T1129"]
    argument_class = RunArguments

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        total_code = ""
        code_path = os.path.dirname(self.agent_code_path) + "/shared/" + task.args.command_line
        try:
            total_code += open(code_path, "r").read() + "\n"
            task.args.add_arg("code", total_code)
        except Exception as e:
            raise Exception("Failed to find code - " + str(e))
        return task


    async def process_response(self, response: AgentResponse):
        pass

        return task

    async def process_response(self, response: AgentResponse):
        pass
