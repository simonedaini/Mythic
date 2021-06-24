from mythic_payloadtype_container.PayloadBuilder import *
from mythic_payloadtype_container.MythicCommandBase import *
import asyncio
import os
from distutils.dir_util import copy_tree
import tempfile

# define your payload type class here, it must extend the PayloadType class though
class MyNewPayload(PayloadType):

    name = "kayn"  # name that would show up in the UI
    file_extension = "py"  # default file extension to use when creating payloads
    author = "@Kayn93"  # author of the payload type
    supported_os = [SupportedOS.Linux]  # supported OS and architecture combos
    wrapper = False  # does this payload type act as a wrapper for another payloads inside of it?
    wrapped_payloads = []  # if so, which payload types. If you are writing a wrapper, you will need to modify this variable (adding in your wrapper's name) in the builder.py of each payload that you want to utilize your wrapper.
    note = "Kayn agent, written in Python3 for Linux"
    supports_dynamic_loading = True  # setting this to True allows users to only select a subset of commands when generating a payload
    build_parameters = {}
    #  the names of the c2 profiles that your agent supports
    c2_profiles = ["http"]
    # after your class has been instantiated by the mythic_service in this docker container and all required build parameters have values
    # then this function is called to actually build the payload
    async def build(self) -> BuildResponse:
        # this function gets called to create an instance of your payload
        resp = BuildResponse(status=BuildStatus.Error)

        try:
            command_code = ""
            for cmd in self.commands.get_commands():
                command_code += (
                    open(self.agent_code_path / "{}.py".format(cmd), "r").read() + "\n\n\n"
                )

            base_code = open(
                self.agent_code_path / "base_agent.py", "r"
            ).read()
            base_code = base_code.replace("UUID_HERE", self.uuid)
            base_code = base_code.replace("# FUNCTIONS", command_code)


            for c2 in self.c2info:
                profile = c2.get_c2profile()["name"]
                f = open('output.txt','w')
                for key, val in c2.get_parameters_dict().items():
                    if key == "headers":
                        for item in val:
                            base_code = base_code.replace(item["key"], item["key"] + "\": \"" + item["value"])
                        f.write(key + " == ")
                        f.write(json.dumps(val) + "\n")
                    elif isinstance(val, dict):
                        base_code = base_code.replace(key, val["enc_key"] if val["enc_key"] is not None else "")
                        f.write(key + " == ")
                        f.write(json.dumps(val) + "\n")
                    elif not isinstance(val, str):
                        base_code = base_code.replace(key, json.dumps(val))
                        f.write(key + " == ")
                        f.write(json.dumps(val) + "\n")
                    else:
                        base_code = base_code.replace(key, val)
                        f.write(key + " == ")
                        f.write(json.dumps(val) + "\n")

                f.flush()
                f.close()

            resp.payload = base_code.encode()
            resp.status = BuildStatus.Success
            resp.message = "Successfully built!"

        except Exception as e:
                    resp.set_status(BuildStatus.Error)
                    resp.set_build_stderr("Error building payload: " + str(e))

        return resp
