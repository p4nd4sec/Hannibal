from mythic_container.MythicCommandBase import *  
from mythic_container.MythicRPC import *

class ExecuteBofArguments(TaskArguments):
    def __init__(self, command_line, **kwargs): 
        super().__init__(command_line, **kwargs)
        
        self.args = [ 
            CommandParameter(
                name="path",
                cli_name="path",
                display_name="Path to execute.",
                type=ParameterType.String,
                description="Path to execute.",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                        group_name="Default",
                        ui_position=0
                    ),
                ]),
        ]
        
    async def parse_arguments(self):
        if len(self.command_line) > 0:
            json_cmd = json.loads(self.command_line)
            self.add_arg("path", json_cmd["path"])
        if self.get_arg("path") is None:
            self.add_arg("path", ".")
        if self.get_arg("path") is not None and self.get_arg("path")[-1] == "\\":
            self.add_arg("path", self.get_arg("path")[:-1])
        
        
class ExecuteBofCommand(CommandBase):
    cmd = "execute_bof"
    needs_admin = False
    help_cmd = "execute_bof path=C:\\\\path\\\\to\\\\file"
    description = "execute_bof" #@p4nd4sec help me have a better description :D 
    version = 1
    author = "@p4nd4sec"
    argument_class = ExecuteBofArguments
    attackmapping = [] #ATT&CK Mapping @p4nd4sec map dj a zai

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        path = taskData.args.get_arg("path")
        # arguments = taskData.args.get_arg("arguments")
        # response.DisplayParams = f"Path: {path}, Arguments: {arguments}"
        response.DisplayParams = f"Path: {path}"
        return response
    
    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp