unit hookutils;

{$MODE Delphi}


interface

uses Classes,sysutils,LCLIntf, LCLType,
  Capstone,CapstoneApi,CapstoneCmn,machapi;


function HookProc(Func, NewFunc: Pointer): Pointer; overload;
function HookProc(DLLName, FuncName: PChar; NewFunc: Pointer): Pointer; overload;

function CalcInterfaceMethodAddr(var AInterface; AMethodIndex: Integer): Pointer;

function HookInterface(var AInterface; AMethodIndex: Integer; NewFunc: Pointer): Pointer;

function UnHook(OldFunc: Pointer): boolean;

type
    THandles = array of THandle;

{$IFDEF windows}
  function SuspendOtherThread(ACode: Pointer; ASize: Integer): THandles;
  procedure ResumOtherThread(threads: THandles);
{$ENDIF}


implementation

const
  PageSize = 4096;
{$IFDEF CPUX64}
{$DEFINE USELONGJMP}
{$ENDIF}

//{$DEFINE USEINT3}  // use it if you know how -  :P ..

type
  ULONG_PTR = NativeUInt;
  POldProc = ^TOldProc;

  PJMPCode = ^TJMPCode;

  TJMPCode = packed record
{$IFDEF USELONGJMP}
    JMP: Word;
    JmpOffset: Int32;
{$ELSE}
    JMP: byte;
{$ENDIF}
    Addr: UIntPtr;
  end;

  TOldProc = packed record
{$IFDEF USEINT3}
    Int3OrNop: byte;
{$ENDIF}
    BackCode: array [0 .. $20 - 1] of byte;
    JmpRealFunc: TJMPCode;
    JmpHookFunc: TJMPCode;

    BackUpCodeSize: Integer;
    OldFuncAddr: Pointer;
  end;

  PNewProc = ^TNewProc;

  TNewProc = packed record
    JMP: byte;
    Addr: Integer;
  end;

function CalcHookCodeSize(Address : Pointer) : Integer;
var
  disasm : TCapstone;
  addr: UInt64;
  insn: TCsInsn;
  TmpSize : Integer;
  BigEnough : Boolean;
begin
  disasm := TCapstone.Create;
  try
    TmpSize := 0;
    BigEnough := false;
    disasm.Mode := [{$IFDEF CPUX64}csm64{$ELSE}csm32{$ENDIF}]; // for x32 & x64 ..
    disasm.Arch := csaX86;
    addr := 0;
    if disasm.Open(Address, $20) = CS_ERR_OK then
    begin
      while disasm.GetNext(addr, insn) do
      begin
        WriteLn(Format('%x  %s %s - size %d', [addr, insn.mnemonic, insn.op_str, insn.size]));
        TmpSize += insn.size;
        if TmpSize >= SizeOf(TNewProc) then
        begin
          BigEnough := true;
          Break;
        end;
      end;
      if not BigEnough then
         TmpSize := 0;
    end else begin
      WriteLn('ERROR! , the Function is small');
    end;
  finally
  //  disasm.Close;
    disasm.Free;
  end;
  Result := TmpSize;
end;
{$ifdef windows}
const
  THREAD_ALL_ACCESS = STANDARD_RIGHTS_REQUIRED or SYNCHRONIZE or $3FF;
function OpenThread(dwDesiredAccess: DWORD; bInheritHandle: BOOL;
  dwThreadId: DWORD): THandle; stdcall; external kernel32;


function SuspendOneThread(dwThreadId: NativeUInt; ACode: Pointer;
  ASize: Integer): THandle;
var
  hThread: THandle;
  dwSuspendCount: DWORD;
  ctx: TContext;
  IPReg: Pointer;
  tryTimes: Integer;
begin
  Result := INVALID_HANDLE_VALUE;
  hThread := OpenThread(THREAD_ALL_ACCESS, FALSE, dwThreadId);
  if (hThread <> 0) and (hThread <> INVALID_HANDLE_VALUE) then
  begin
    dwSuspendCount := SuspendThread(hThread);

    if dwSuspendCount <> DWORD(-1) then
    begin
      while (GetThreadContext(hThread, ctx)) do
      begin
        tryTimes := 0;
        IPReg := Pointer({$IFDEF CPUX64}ctx.Rip{$ELSE}ctx.EIP{$ENDIF});
        if (NativeInt(IPReg) >= NativeInt(ACode)) and
          (NativeInt(IPReg) <= (NativeInt(ACode) + ASize)) then
        begin
          ResumeThread(hThread);
          Sleep(100);
          SuspendThread(hThread);
          Inc(tryTimes);
          if tryTimes > 5 then
          begin
            Break;
          end;
        end
        else
        begin
          Result := hThread;
          Break;
        end;
      end;
    end;
  end;
end;

function SuspendOtherThread(ACode: Pointer; ASize: Integer): THandles;
var
  hSnap: THandle;
  te: THREADENTRY32;
  nThreadsInProcess: DWORD;
  hThread: THandle;
begin
  Exit;
  hSnap := CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, GetCurrentProcessId());
  te.dwSize := SizeOf(te);

  nThreadsInProcess := 0;
  if (Thread32First(hSnap, te)) then
  begin
    while True do
    begin
      if (te.th32OwnerProcessID = GetCurrentProcessId()) then
      begin

        if (te.th32ThreadID <> GetCurrentThreadId()) then
        begin
          hThread := SuspendOneThread(te.th32ThreadID, ACode, ASize);
          if hThread <> INVALID_HANDLE_VALUE then
          begin
            Inc(nThreadsInProcess);
            SetLength(Result, nThreadsInProcess);
            Result[nThreadsInProcess - 1] := hThread;
          end;
        end
      end;
      te.dwSize := SizeOf(te);
      if not Thread32Next(hSnap, te) then
        Break;
    end;
    // until not Thread32Next(hSnap, te);
  end;

  FileClose(hSnap); { *Converted from CloseHandle* }
end;

procedure ResumOtherThread(threads: THandles);
var
  i: Integer;
begin
  Exit;
  for i := Low(threads) to High(threads) do
  begin
    ResumeThread(threads[i]);
    FileClose(threads[i]); { *Converted from CloseHandle* }
  end;
end;
{$endif}

function TryAllocMem(APtr: Pointer; ASize: Cardinal): Pointer;
{$ifdef windows}
const
  KB: Int64 = 1024;
  MB: Int64 = 1024 * 1024;
  GB: Int64 = 1024 * 1024 * 1024;
var
  mbi: TMemoryBasicInformation;
  Min, Max: Int64;
  pbAlloc: Pointer;
  sSysInfo: TSystemInfo;
  {$endif}
begin
  Result := nil;
{$ifdef windows}
  GetSystemInfo(sSysInfo);
  Min := NativeUInt(APtr) - 2 * GB;
  if Min <= 0 then
    Min := 1;
  Max := NativeUInt(APtr) + 2 * GB;

  pbAlloc := Pointer(Min);
  while NativeUInt(pbAlloc) < Max do
  begin
    if (VirtualQuery(pbAlloc, mbi, SizeOf(mbi)) = 0) then
      Break;
    if ((mbi.State or MEM_FREE) = MEM_FREE) and (mbi.RegionSize >= ASize) and
      (mbi.RegionSize >= sSysInfo.dwAllocationGranularity) then
    begin
      pbAlloc :=
        PByte(ULONG_PTR((ULONG_PTR(pbAlloc) + (sSysInfo.dwAllocationGranularity
        - 1)) div sSysInfo.dwAllocationGranularity) *
        sSysInfo.dwAllocationGranularity);
      Result := VirtualAlloc(pbAlloc, ASize, MEM_COMMIT or MEM_RESERVE
{$IFDEF CPUX64}
        or MEM_TOP_DOWN
{$ENDIF}
        , PAGE_EXECUTE_READWRITE);
      if Result <> nil then
        Break;
    end;
    pbAlloc := Pointer(NativeUInt(mbi.BaseAddress) + mbi.RegionSize);
  end;
{$endif}
{$ifdef darwin}  // Mac OS X ..
        Result := AllocMem(ASize); // just for testing ..
{$endif}
{$ifdef linux}
 { TODO -oColdzer0 : Add Linux Memory Allocation }
{$endif}
end;


function HookProc(DLLName, FuncName: PChar; NewFunc: Pointer): Pointer;
var
  {$ifdef windows}
  h: HMODULE;
  {$else}
  h : TlibHandle; // for both Mac & linux ..
  {$endif}
begin
  Result := nil;
  {$ifdef windows}
  h := GetModuleHandle(DLLName); // this's a Win API ..
  if h = 0 then
  {$endif}
  h := LoadLibrary(DLLName); // Multi OS ..
  if h = 0 then
    Exit;
  Result := HookProc(GetProcAddress(h, FuncName), NewFunc);
end;

function HookProc(Func, NewFunc: Pointer): Pointer;
var
  oldProc: POldProc;
  newProc: PNewProc;
  backCodeSize: {$IFDEF dinwos}Integer{$endif}{$ifdef darwin}mach_vm_size_t{$endif};
  newProtected, oldProtected: DWORD;
  threads: THandles;
  nOriginalPriority: Integer;
  JmpAfterBackCode: PJMPCode;
  OldPtr : Pointer;
begin
  Result := nil;
  if (Func = nil) or (NewFunc = nil) then
    Exit;
  newProc := PNewProc(Func);
  backCodeSize := CalcHookCodeSize(Func); // Already Multi OS ..
  if backCodeSize < 0 then
    Exit;
  {$ifdef windows}
  nOriginalPriority := GetThreadPriority(GetCurrentThread());
  SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
  threads := SuspendOtherThread(Func, backCodeSize);
  {$endif}
  try
    {$ifdef darwin}
    if mach_vm_protect(mach_task_self,mach_vm_address_t(Func),backCodeSize,false,VM_PROT_ALL) <> KERN_SUCCESS then
    {$endif}
    {$ifdef windows}
    if not VirtualProtect(Func, backCodeSize, PAGE_EXECUTE_READWRITE,oldProtected) then
    {$endif}
      Exit;
    //

    Result := TryAllocMem(Func, PageSize);

    {$ifdef darwin}
    if mach_vm_protect(mach_task_self,mach_vm_address_t(Result),PageSize,false,VM_PROT_ALL) <> KERN_SUCCESS then
    WriteLn('Error , TryAllocMem <<<<');
    {$endif}
    // VirtualAlloc(nil, PageSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if Result = nil then
      Exit;

    FillByte(Result^, SizeOf(TOldProc), $90);
    oldProc := POldProc(Result);
{$IFDEF USEINT3}
    oldProc.Int3OrNop := $CC;
{$ENDIF}
    oldProc.BackUpCodeSize := backCodeSize;
    oldProc.OldFuncAddr := Func;
    //  CopyMemory(des,src,sz);
    //  Move(src,des,sz);
    OldPtr := @oldProc^.BackCode;
    system.move(Func^,OldPtr^, backCodeSize);

    JmpAfterBackCode := PJMPCode(@oldProc^.BackCode[backCodeSize]);
{$IFDEF USELONGJMP}
    oldProc^.JmpRealFunc.JMP := $25FF;
    oldProc^.JmpRealFunc.JmpOffset := 0;
    oldProc^.JmpRealFunc.Addr := UIntPtr(Int64(Func) + backCodeSize);

    JmpAfterBackCode^.JMP := $25FF;
    JmpAfterBackCode^.JmpOffset := 0;
    JmpAfterBackCode^.Addr := UIntPtr(Int64(Func) + backCodeSize);

    oldProc^.JmpHookFunc.JMP := $25FF;
    oldProc^.JmpHookFunc.JmpOffset := 0;
    oldProc^.JmpHookFunc.Addr := UIntPtr(NewFunc);
{$ELSE}
    oldProc^.JmpRealFunc.JMP := $E9;
    oldProc^.JmpRealFunc.Addr := (NativeInt(Func) + backCodeSize) -
      (NativeInt(@oldProc^.JmpRealFunc) + 5);

    oldProc^.JmpHookFunc.JMP := $E9;
    oldProc^.JmpHookFunc.Addr := NativeInt(NewFunc) -
      (NativeInt(@oldProc^.JmpHookFunc) + 5);
{$ENDIF}
    //
    FillByte(Func^, backCodeSize, $90);

    newProc^.JMP := $E9;
    newProc^.Addr := NativeInt(@oldProc^.JmpHookFunc) - (NativeInt(@newProc^.JMP) + 5);
    // NativeInt(NewFunc) - (NativeInt(@newProc^.JMP) + 5);


    {$ifdef darwin}
    if mach_vm_protect(mach_task_self,mach_vm_address_t(Func),backCodeSize,false,VM_PROT_ALL) <> KERN_SUCCESS then
    {$endif}
    {$ifdef windows}
    if not VirtualProtect(Func, backCodeSize, oldProtected, newProtected) then
    {$endif}
      Exit;
   {$ifdef windows}
    FlushInstructionCache(GetCurrentProcess(), newProc, backCodeSize);
    FlushInstructionCache(GetCurrentProcess(), oldProc, PageSize);
   {$endif}
  finally
  {$ifdef windows}
    ResumOtherThread(threads);
    SetThreadPriority(GetCurrentThread(), nOriginalPriority);
  {$endif}
  end;
end;

function UnHook(OldFunc: Pointer): boolean;
var
  oldProc: POldProc ABSOLUTE OldFunc;
  newProc: PNewProc;
  backCodeSize: Integer;
  newProtected, oldProtected: DWORD;
  threads: THandles;
  nOriginalPriority: Integer;
  addr : pointer;
begin
  Result := FALSE;
  if (OldFunc = nil) then
    Exit;   // oldProc^.OldFuncAddr	POINTER	$11300

  backCodeSize := oldProc^.BackUpCodeSize;
  newProc := PNewProc(oldProc^.OldFuncAddr);
  {$ifdef windows}
  nOriginalPriority := GetThreadPriority(GetCurrentThread());
  SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
  threads := SuspendOtherThread(oldProc, SizeOf(TOldProc));
  {$endif}
  try
    {$ifdef darwin}
    if mach_vm_protect(mach_task_self,mach_vm_address_t(newProc),backCodeSize,false,VM_PROT_ALL) <> KERN_SUCCESS then
    {$endif}
    {$ifdef windows}
    if not VirtualProtect(newProc, backCodeSize, PAGE_EXECUTE_READWRITE,oldProtected) then
    {$endif}
    Exit;
    // keep this hit to help :P ..
    //  CopyMemory(des,src,sz);
    //  Move(src,des,sz);
    {$ifdef darwin}    // addr	POINTER	$14402C0

    addr := @oldProc^.BackCode;
    system.move(addr^,newProc^, oldProc^.BackUpCodeSize);
    {$endif}
    {$ifdef windows}
    CopyMemory(newProc, @oldProc^.BackCode, oldProc^.BackUpCodeSize);
     {$endif}

   {$ifdef darwin}
   newProc := PNewProc(oldProc^.OldFuncAddr);
   if mach_vm_protect(mach_task_self,mach_vm_address_t(newProc),backCodeSize,false,VM_PROT_ALL) <> KERN_SUCCESS then
   {$endif}
   {$ifdef windows}
    if not VirtualProtect(newProc, backCodeSize, oldProtected, newProtected) then
    {$endif}
      Exit;
    {$ifdef windows}
    VirtualFree(oldProc, PageSize, MEM_FREE);
    FlushInstructionCache(GetCurrentProcess(), newProc, backCodeSize);
    {$endif}
    {$ifdef darwin}
    Freemem(oldProc,PageSize);
    {$endif}
  finally
    {$ifdef windows}
    ResumOtherThread(threads);
    SetThreadPriority(GetCurrentThread(), nOriginalPriority);
    {$endif}
    Result := True;
  end;
end;

function CalcInterfaceMethodAddr(var AInterface; AMethodIndex: Integer)
  : Pointer;
type
  TBuf = array [0 .. $FF] of byte;
  PBuf = ^TBuf;
var
  pp: PPointer;
  buf: PBuf;
begin
  pp := PPointer(AInterface)^;
  Inc(pp, AMethodIndex);
  Result := pp^;

  buf := Result;

{$IFDEF CPUX64}
  if (buf^[0] = $48) and (buf^[1] = $81) and (buf^[2] = $C1) and (buf^[7] = $E9)
  then
    Result := Pointer(NativeInt(@buf[$C]) + PDWORD(@buf^[8])^);
{$ELSE}
  if (buf^[0] = $81) and (buf^[1] = $44) and (buf^[2] = $24) and
    (buf^[03] = $04) and (buf^[8] = $E9) then
    Result := Pointer(NativeInt(@buf[$D]) + PDWORD(@buf^[9])^)
  else
    if (buf^[0] = $05) and (buf^[5] = $E9) then
      Result := Pointer(NativeInt(@buf[$A]) + PDWORD(@buf^[6])^);
{$ENDIF}
end;

function HookInterface(var AInterface; AMethodIndex: Integer;
  NewFunc: Pointer): Pointer;
begin
  Result := HookProc(CalcInterfaceMethodAddr(AInterface, AMethodIndex),
    NewFunc);
end;

end.

