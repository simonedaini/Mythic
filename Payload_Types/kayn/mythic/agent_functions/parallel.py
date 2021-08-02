from mythic_payloadtype_container.MythicCommandBase import *
import json
from mythic_payloadtype_container.MythicRPC import *

class ParallelArguments(TaskArguments):
    def __init__(self, command_line):
        super().__init__(command_line)
        self.args = {}

    async def parse_arguments(self):
        if len(self.command_line.split()) < 2:
            raise ValueError("Usage: parallel </shared/file_name.py> <#workers> <parameters>")
        pass
        params = self.command_line.split(" ")
        self.add_arg("file_name", params[0])
        self.add_arg("workers", params[1])

        if len(self.command_line.split()) >= 2:
            self.add_arg("parameters", params[2:])



class ParallelCommand(CommandBase):
    cmd = "parallel"
    needs_admin = False
    help_cmd = "parallel </shared/file_name.py> <#workers>"
    description = "Run the worker function in file.py in parallel on <workers> agents passing <param_list> parameters"
    version = 1
    supported_ui_features = [""]
    author = "@Kayn93"
    parameters = []
    attackmapping = []
    argument_class = ParallelArguments

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        return task

    async def process_response(self, response: AgentResponse):
        pass