from mythic_payloadtype_container.MythicCommandBase import *
import json


class BreakerArguments(TaskArguments):
    def __init__(self, command_line):
        super().__init__(command_line)
        self.args = {}

    async def parse_arguments(self):
        pass


class BreakerCommand(CommandBase):
    cmd = "breaker"
    needs_admin = False
    help_cmd = "break"
    description = "This stops the current execution of a function"
    version = 1
    supported_ui_features = []
    author = "@Kayn93"
    argument_class = BreakerArguments
    attackmapping = []

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        return task

    async def process_response(self, response: AgentResponse):
        pass

