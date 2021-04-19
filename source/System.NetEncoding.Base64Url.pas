unit System.NetEncoding.Base64Url;

interface

uses
  System.SysUtils, System.Classes, System.NetEncoding;

type
  TBase64UrlEncoding = class(TBase64Encoding)
  protected
    function DoDecode(const Input, Output: TStream): NativeInt; override;
    function DoDecode(const Input: array of Byte): TBytes; overload; override;
    function DoEncode(const Input, Output: TStream): NativeInt; override;
    function DoEncode(const Input: array of Byte): TBytes; overload; override;
    function DoDecodeStringToBytes(const Input: string): TBytes; override;
    function DoEncodeBytesToString(const Input: Pointer; Size: Integer): string;
        overload; override;
  end;

  TNetEncodingHelper = class helper for TNetEncoding
  private
    class var FBase64UrlEncoding: TNetEncoding;
    class function GetBase64UrlEncoding: TNetEncoding; static;
  public
    class destructor Destroy;
    class property Base64Url: TNetEncoding read GetBase64UrlEncoding;
  end;

implementation

uses System.RTLConsts;

function TBase64UrlEncoding.DoDecode(const Input: array of Byte): TBytes;
begin
  var s: TBytes;
  SetLength(s, Length(Input));
  var c: Byte;
  var i: Integer;
  for i := Low(Input) to High(Input) do begin
    c := Input[i];
    if c = $2D{-} then
      s[i] := $2B{+}
    else if c = $5F{_} then
      s[i] := $2F{/}
    else
      s[i] := c;
  end;
  var iPadding := 4 - Length(Input) mod 4;
  if iPadding = 1 then
    s := s + [$3D{=}]
  else if iPadding = 2 then
    s := s + [$3D{=}, $3D{=}];
  Result := inherited DoDecode(s);
end;

function TBase64UrlEncoding.DoDecode(const Input, Output: TStream): NativeInt;
begin
  raise Exception.CreateResFmt(@StrEActionNoSuported, [ClassName]);
end;

function TBase64UrlEncoding.DoDecodeStringToBytes(const Input: string): TBytes;
begin
  var s := Input;
  var c: Char;
  var i: Integer;
  for i := 0 to s.Length - 1 do begin
    c := s[i];
    if c = '-' then
      s[i] := '+'
    else if c = '_' then
      s[i] := '/'
  end;
  var iPadding := 4 - Input.Length mod 4;
  if iPadding = 1 then
    s := s + '='
  else if iPadding = 2 then
    s := s + '==';
  Result := inherited DoDecodeStringToBytes(s);
end;

function TBase64UrlEncoding.DoEncode(const Input, Output: TStream): NativeInt;
begin
  raise Exception.CreateResFmt(@StrEActionNoSuported, [ClassName]);
end;

function TBase64UrlEncoding.DoEncode(const Input: array of Byte): TBytes;
begin
  Result := inherited;
  var c: Byte;
  var i: Integer;
  for i := Low(Result) to High(Result) do begin
    c := Result[i];
    if c = $2B {+} then
      Result[i] := $2D {-}
    else if c = $2F {/} then
      Result[i] := $5F{_}
    else if c = $3D{=} then Break;
  end;
  if (i <= Length(Result)) then SetLength(Result, i);
end;

function TBase64UrlEncoding.DoEncodeBytesToString(const Input: Pointer; Size:
    Integer): string;
begin
  var s := inherited;
  var c: Char;
  var i: Integer;
  for i := 1 to s.Length do begin
    c := s[i];
    if c = '+' then
      s[i] := '-'
    else if c = '/' then
      s[i] := '_'
    else if c = '=' then Break;
  end;
  if (i <= s.Length) then SetLength(s, i - 1);
  Result := s;
end;

class function TNetEncodingHelper.GetBase64UrlEncoding: TNetEncoding;
var LEncoding: TBase64Encoding;
begin
  if FBase64UrlEncoding = nil then
  begin
    LEncoding := TBase64UrlEncoding.Create(0);
    if AtomicCmpExchange(Pointer(FBase64UrlEncoding), Pointer(LEncoding), nil) <> nil then
      LEncoding.Free
{$IFDEF AUTOREFCOUNT}
    else
      FBase64UrlEncoding.__ObjAddRef
{$ENDIF AUTOREFCOUNT};
  end;
  Result := FBase64UrlEncoding;
end;

class destructor TNetEncodingHelper.Destroy;
begin
  FreeAndNil(FBase64UrlEncoding);
end;

end.
