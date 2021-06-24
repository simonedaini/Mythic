from mythic_payloadtype_container.MythicCommandBase import *
import json


class P2PServerArguments(TaskArguments):
    def __init__(self, command_line):
        super().__init__(command_line)
        self.args = {}

    async def parse_arguments(self):
        pass


class P2PServerCommand(CommandBase):
    cmd = "p2p_server"
    needs_admin = False
    help_cmd = "p2p_server"
    description = "Enables an agent to start listening for p2p connections"
    version = 1
    supported_ui_features = [""]
    author = ""
    argument_class = P2PServerArguments
    attackmapping = []

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        return task

    async def process_response(self, response: AgentResponse):
        pass
