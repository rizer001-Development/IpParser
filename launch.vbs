' IP Parser - silent launcher (no console window at all).
' Double-click this file instead of launch.bat to hide the console completely.
Set fso = CreateObject("Scripting.FileSystemObject")
Set sh  = CreateObject("WScript.Shell")
sh.CurrentDirectory = fso.GetParentFolderName(WScript.ScriptFullName)
sh.Run "launch.bat", 0, False
