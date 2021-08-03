from mythic_payloadtype_container.MythicCommandBase import *
import json


class StopArguments(TaskArguments):
    def __init__(self, command_line):
        super().__init__(command_line)
        self.args = {}

    async def parse_arguments(self):
        if len(self.command_line.split()) < 1:
            raise ValueError("Usage: stop <function_name>")
        params = self.command_line.split(" ")
        self.add_arg("function_name", params[0])


class StopCommand(CommandBase):
    cmd = "stop"
    needs_admin = False
    help_cmd = "stop"
    description = "This stops the current execution of a function"
    version = 1
    supported_ui_features = []
    author = "@Kayn93"
    argument_class = StopArguments
    attackmapping = []

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        return task

    async def process_response(self, response: AgentResponse):
        pass

