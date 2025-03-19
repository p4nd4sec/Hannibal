from mythic_container.MythicCommandBase import *  
from mythic_container.MythicRPC import *

class ExecuteBofArguments(TaskArguments):
    def __init__(self, command_line, **kwargs): 
        super().__init__(command_line, **kwargs)
        
        self.args = [ 
            CommandParameter(
                name="path",
                type=ParameterType.String,
                description="I think it is some sort of path...", #@p4nd4sec help me have a better description :D
                parameter_group_info=ParameterGroupInfo(required=True)
            ),
            CommandParameter(
                name="arguments",
                type=ParameterType.String,
                description="I think it is arguments..", #@p4nd4sec help me have a better description :D
                parameter_group_info=ParameterGroupInfo(required=False)
            )
        ]
        
    async def parse_arguments(self):
        self.load_args_from_json_string(self.command_line)
        if "path" not in self.command_line_json:
            raise Exception("path is a required argument")
        if "arguments" not in self.command_line_json:
            self.add_arg("arguments", "")
        else:
            self.add_arg("arguments", self.command_line_json["arguments"])
        self.add_arg("path", self.command_line_json["path"])
        logger.debug(f"Arguments: {self.args}")
        
        
class ExecuteBofCommand(CommandBase):
    cmd = "execute_bof"
    needs_admin = False
    help_cmd = "execute_bof path=C:\\\\path\\\\to\\\\file arguments=\"arg1 arg2 arg3\""
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
        arguments = taskData.args.get_arg("arguments")
        response.DisplayParams = f"Path: {path}, Arguments: {arguments}"
        return response
    
    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp