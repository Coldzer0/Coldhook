program DISASSM;

{$mode Delphi}{$H+}
{$IFDEF UNIX}
  {$define UseCThreads}
{$ENDIF}

uses
  {$IFDEF UNIX}{$IFDEF UseCThreads}
  cthreads,
  {$ENDIF}{$ENDIF}
  Classes,sysutils,machapi,hookutils
  { you can add units after this };

var
//  ptr : Pointer;
  PID : integer;
  port : mach_port_name_t;
begin
     PID := 0;
     port := 0;
     if task_for_pid(mach_task_self,2756,port) = KERN_SUCCESS then
     begin
          writeln('Port : ',port);
          if task_resume(port) = KERN_SUCCESS then
          writeln('task_resume ok');
     end
     else
         writeln('Error : ', GetLastOSError);

     writeln('======================================================' );
end.

