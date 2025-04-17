from mythic_container.MythicCommandBase import *  
from mythic_container.MythicRPC import *

class ExecuteBofArguments(TaskArguments):
    def __init__(self, command_line, **kwargs): 
        super().__init__(command_line, **kwargs)
        
        self.args = [
            CommandParameter(
                name="bof",
                type=ParameterType.File,
                description="Upload BoF file to be executed. Be aware a UINT32 cannot be > 4294967295.",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True,
                        ui_position=0,
                        )
                    ],
            ),
            CommandParameter(
                name="bof_arguments",
                cli_name="Arguments",
                display_name="Arguments",
                type=ParameterType.TypedArray,
                default_value=[],
                choices=["int32", "string", "wchar"], 
                description="""Arguments to pass to the BoF via the following way:
                -i:123 or int32:123
                -z:hello or string:hello
                -Z:hello or wchar:hello
                -b:abc== or base64:abc==""",
                typedarray_parse_function=self.get_arguments,
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                        group_name="Default",
                        ui_position=1
                    ),
                ]),
            CommandParameter(
                name="additional_file",
                cli_name="AdditionalFile",
                display_name="Additional File (Optional)",
                default_value=None,
                type=ParameterType.File,
                description="Additional file to be passed along to the BoF. Optional.",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                        group_name="Default",
                        ui_position=2
                    ),
                ]
            )
        ]
        
    async def get_arguments(self, arguments: PTRPCTypedArrayParseFunctionMessage) -> PTRPCTypedArrayParseFunctionMessageResponse:
        argumentResponse = PTRPCTypedArrayParseFunctionMessageResponse(Success=True)
        argumentSplitArray = []
        
        for argValue in arguments.InputArray:
            argSplitResult = argValue.split(" ")
            for spaceSplitArg in argSplitResult:
                argumentSplitArray.append(spaceSplitArg)

        bof_arguments = []

        for argument in argumentSplitArray:
            argType,value = argument.split(":",1)
            value = value.strip("\'").strip("\"")
            
            if argType == "":
                pass
            elif argType == "int32" or argType == "-i":
                bof_arguments.append(["int32",int(value)])
            elif argType == "string" or argType == "-z":
                bof_arguments.append(["string",value])
            elif argType == "wchar" or argType == "-Z":
                bof_arguments.append(["wchar",value])
            else:
                return PTRPCTypedArrayParseFunctionMessageResponse(Success=False, Error=f"Failed to parse argument: {argument}: Unknown value type.")

        argumentResponse = PTRPCTypedArrayParseFunctionMessageResponse(Success=True, TypedArray=bof_arguments)
        
        return argumentResponse
    
    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == "{":
                self.load_args_from_json_string(self.command_line)
        
class ExecuteBofCommand(CommandBase):
    cmd = "execute_bof"
    needs_admin = False
    help_cmd = "execute_bof"
    description = "Execute BoF file with arguments" #@p4nd4sec help me have a better description :D 
    version = 1
    author = "@p4nd4sec && @h114mx001"
    argument_class = ExecuteBofArguments
    attackmapping = [] #ATT&CK Mapping @p4nd4sec map dj a zai
    attributes = CommandAttributes(
        load_only=False,
        builtin=False,
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )

        fData = FileData()
        fData.AgentFileId = taskData.args.get_arg("bof")
        file = await SendMythicRPCFileGetContent(fData)

        if file.Success:
            taskData.args.add_arg("file_size", len(file.Content))
            taskData.args.add_arg("raw", file.Content)
        else:
            raise Exception("Failed to get file contents: " + file.Error)

        fData_additional = FileData()
        
        fData_additional.AgentFileId = taskData.args.get_arg("additional_file")
        if fData_additional.AgentFileId is not None:
            file_additional = await SendMythicRPCFileGetContent(fData_additional)

            if file_additional.Success:
                if (len(file_additional.Content) > 0):
                    taskData.args.add_arg("additional_file_size", len(file_additional.Content))
                    taskData.args.add_arg("additional_file_raw", file_additional.Content)      
        else: 
            # hannibal don't lile null stuff, som I am here to please him :D
            import os
            taskData.args.add_arg("additional_file_size", 16)
            taskData.args.add_arg("additional_file_raw", os.urandom(16))
            # raise Exception("Failed to get file contents: " + file_additional.Error)
        
        response.DisplayParams = ""
        
        return response
    
    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp