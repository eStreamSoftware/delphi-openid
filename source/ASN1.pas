unit ASN1;

interface

uses System.SysUtils;

type
  TInt64Helper = record helper for Int64
    function ToBigEndian: TBytes;
  end;

  TASN1_DataType = (
    asnBoolean          = $01,
    asnInteger          = $02,
    asnBitString        = $03,
    asnOctetString      = $04,
    asnNull             = $05,
    asnObjectIdentifier = $06,
    asnSequence         = $30
  );

  TASN1_DataTypeHelper = record helper for TASN1_DataType
    function Tag: Byte; inline;
    function Tags: TBytes; inline;
  end;

  TASN1_Field = record
  strict private
    FDataType: TASN1_DataType;
    FValue: Pointer;
    procedure DisposeField;
  public
    procedure SetValue(const [ref] aValue);
    class operator Assign(var Dest: TASN1_Field; const [ref] Src: TASN1_Field);
    class operator Finalize(var Dest: TASN1_Field);
    class operator Initialize(out Dest: TASN1_Field);
    function GetValue<T>: T;
    property DataType: TASN1_DataType read FDataType;
    property Value: Pointer read FValue;
  end;

  TASN1_Fields = record
  strict private
    FFields: TArray<TASN1_Field>;
  public
    procedure Add(const [ref] aField); overload;
    class operator Initialize(out Dest: TASN1_Fields);
    property Fields: TArray<TASN1_Field> read FFields;
  end;

  TASN1_Boolean = record
  strict private
    FDataType: TASN1_DataType;  // Do not move
    FValue: Boolean;
  public
    class function DataType: TASN1_DataType; static;
    class operator Implicit(aValue: Boolean): TASN1_Boolean;
    class operator Implicit(aValue: TASN1_Boolean): Boolean;
    class operator Initialize(out Dest: TASN1_Boolean);
    property Value: Boolean read FValue write FValue;
  end;

  TASN1_Integer = record
  strict private
    FDataType: TASN1_DataType;  // Do not move
    FValue: TBytes;
    FIsPositive: Boolean;
  public
    function DataSize: Cardinal;
    class function DataType: TASN1_DataType; static;
    class operator Implicit(aValue: Int64): TASN1_Integer;
    class operator Implicit(aValue: TBytes): TASN1_Integer;
    class operator Initialize(out Dest: TASN1_Integer);
    property IsPositive: Boolean read FIsPositive;
    property Value: TBytes read FValue;
  end;

  TASN1_BitString = record
  strict private
    FDataType: TASN1_DataType;  // Do not move
    FValue: TBytes;
    FUnusedBits: Byte;
  public
    function DataSize: Cardinal;
    class function DataType: TASN1_DataType; static;
    class operator Implicit(aValue: TBytes): TASN1_BitString;
    class operator Initialize(out Dest: TASN1_BitString);
    property Value: TBytes read FValue;
    property UnusedBits: Byte read FUnusedBits;
  end;

  TASN1_OctetString = record
  strict private
    FDataType: TASN1_DataType;  // Do not move
  public
    class function DataType: TASN1_DataType; static;
    class operator Initialize(out Dest: TASN1_OctetString);
  end;

  TASN1_Null = record
  strict private
    FDataType: TASN1_DataType;  // Do not move
  public
    class function DataType: TASN1_DataType; static;
    class operator Initialize(out Dest: TASN1_Null);
  end;

  TASN1_ObjectIdentifier = record
  strict private
    FDataType: TASN1_DataType;  // Do not move
    FValue: string;
  public
    class function DataType: TASN1_DataType; static;
    class operator Implicit(aValue: string): TASN1_ObjectIdentifier;
    class operator Initialize(out Dest: TASN1_ObjectIdentifier);
    property Value: string read FValue;
  end;

  TASN1_Sequence = record
  strict private
    FDataType: TASN1_DataType;  // Do not move
    FValue: TASN1_Fields;
  public
    class function DataType: TASN1_DataType; static;
    procedure Add(const [ref] aField);
    procedure AddNull;
    class operator Initialize(out Dest: TASN1_Sequence);
    property Value: TASN1_Fields read FValue;
  end;

  TASN1_DER = class sealed
  {https://docs.microsoft.com/en-us/windows/win32/seccertenroll/distinguished-encoding-rules}
  public
    class function EncodeLength(aLen: Int64): TBytes;
    class function Encode(const [ref] aField: TASN1_Boolean): TBytes; overload;
    class function Encode(const [ref] aField: TASN1_Integer): TBytes; overload;
    class function Encode(const [ref] aField: TASN1_BitString): TBytes; overload;
    class function Encode(const [ref] aField: TASN1_Null): TBytes; overload;
    class function Encode(const [ref] aField: TASN1_ObjectIdentifier): TBytes; overload;
    class function Encode(const [ref] aField: TASN1_Sequence): TBytes; overload;
  end;

  TPEM = record
  // rfc7468
  const Hyphens = '-----';
  strict private
    FLabel: string;
    FValue: TBytes;
    function BeginMarker: string;
    function EndMarker: string;
  public
    class operator Implicit(aValue: TPEM): string;
    class operator Implicit(aValue: string): TPEM;
    class operator Initialize(out Dest: TPEM);
    procedure SetValue(aLabel: string; aValue: TBytes);
  end;

implementation

uses System.NetEncoding, System.RTLConsts;

type
  TBase64EncodingHelper = class helper for TBase64Encoding
  public
    function LineSeparator: string;
  end;

function TInt64Helper.ToBigEndian: TBytes;
begin
  var a := $FF00000000000000;
  var b := a;  // make sure b has same data type as variable a
  if Self >= 0 then b := 0;

  var i := 0;
  while Self and a = b do begin
    a := a shr 8;
    if a = 0 then Break;
    Inc(i);
    if Self < 0 then b := a;
  end;

  SetLength(Result, SizeOf(Self) - i);
  for var j := Low(Result) to High(Result) do
    Result[High(Result) - j] := (Self shr (j * 8)) and $FF;
end;

function TASN1_DataTypeHelper.Tag: Byte;
begin
  Result := Byte(Self);
end;

function TASN1_DataTypeHelper.Tags: TBytes;
begin
  Result := [Tag];
end;

function TBase64EncodingHelper.LineSeparator: string;
begin
  Result := FLineSeparator;
end;

procedure TASN1_Field.DisposeField;
var f1: ^TASN1_Boolean;
    f2: ^TASN1_Integer;
    f3: ^TASN1_BitString;
    f4: ^TASN1_OctetString;
    f5: ^TASN1_Null;
    f6: ^TASN1_ObjectIdentifier;
    f30:^TASN1_Sequence;
begin
  if Value = nil then Exit;

  case FDataType of
    asnBoolean: begin
      f1 := Value;
      Dispose(f1);
    end;
    asnInteger: begin
      f2 := Value;
      Dispose(f2);
    end;
    asnBitString: begin
      f3 := Value;
      Dispose(f3);
    end;
    asnOctetString: begin
      f4 := Value;
      Dispose(f4);
    end;
    asnNull: begin
      f5 := Value;
      Dispose(f5);
    end;
    asnObjectIdentifier: begin
      f6 := Value;
      Dispose(f6);
    end;
    asnSequence: begin
      f30 := Value;
      Dispose(f30);
    end;
    else
      raise Exception.CreateResFmt(@SInvalidPropertyType, [FDataType.Tag.ToString]);
  end;
  FValue := nil;
end;

procedure TASN1_Field.SetValue(const [ref] aValue);
var f1: ^TASN1_Boolean;
    f2: ^TASN1_Integer;
    f3: ^TASN1_BitString;
    f4: ^TASN1_OctetString;
    f5: ^TASN1_Null;
    f6: ^TASN1_ObjectIdentifier;
    f30:^TASN1_Sequence;
begin
  // Expect first byte of record structure to contain data type
  FDataType := TASN1_DataType(TBytes(@aValue)[0]);

  case FDataType of
    asnBoolean: begin
      New(f1);
      f1^ := TASN1_Boolean(aValue);
      FValue := Pointer(f1);
    end;
    asnInteger: begin
      New(f2);
      f2^ := TASN1_Integer(aValue);
      FValue := Pointer(f2);
    end;
    asnBitString: begin
      New(f3);
      f3^ := TASN1_BitString(aValue);
      FValue := Pointer(f3);
    end;
    asnOctetString: begin
      New(f4);
      f4^ := TASN1_OctetString(aValue);
      FValue := Pointer(f4);
    end;
    asnNull: begin
      New(f5);
      f5^ := TASN1_Null(aValue);
      FValue := Pointer(f5);
    end;
    asnObjectIdentifier: begin
      New(f6);
      f6^ := TASN1_ObjectIdentifier(aValue);
      FValue := Pointer(f6);
    end;
    asnSequence: begin
      New(f30);
      f30^ := TASN1_Sequence(aValue);
      FValue := Pointer(f30);
    end;
    else
      raise Exception.CreateResFmt(@SInvalidPropertyType, [FDataType.Tag.ToString]);
  end;
end;

class operator TASN1_Field.Assign(var Dest: TASN1_Field;
  const [ref] Src: TASN1_Field);
begin
  Dest.DisposeField;
  Dest.SetValue(Src.Value^);
end;

class operator TASN1_Field.Finalize(var Dest: TASN1_Field);
begin
  Dest.DisposeField;
end;

function TASN1_Field.GetValue<T>: T;
begin
  Result := T(Value^);
end;

class operator TASN1_Field.Initialize(out Dest: TASN1_Field);
begin
  Dest.FValue := nil;
end;

procedure TASN1_Fields.Add(const [ref] aField);
begin
  var i := Length(FFields);
  SetLength(FFields, i + 1);
  FFields[i].SetValue(aField);
end;

class operator TASN1_Fields.Initialize(out Dest: TASN1_Fields);
begin
  Dest.FFields := [];
end;

class function TASN1_Boolean.DataType: TASN1_DataType;
begin
  Result := asnBoolean;
end;

class operator TASN1_Boolean.Implicit(aValue: Boolean): TASN1_Boolean;
begin
  Result.FValue := aValue;
end;

class operator TASN1_Boolean.Implicit(aValue: TASN1_Boolean): Boolean;
begin
  Result := aValue.FValue;
end;

class operator TASN1_Boolean.Initialize(out Dest: TASN1_Boolean);
begin
  Dest.FDataType := Dest.DataType;
end;

function TASN1_Integer.DataSize: Cardinal;
begin
  Result := Length(FValue);
end;

class function TASN1_Integer.DataType: TASN1_DataType;
begin
  Result := asnInteger;
end;

class operator TASN1_Integer.Implicit(aValue: Int64): TASN1_Integer;
begin
  Result.FValue := aValue.ToBigEndian;
  Result.FIsPositive := aValue >= 0;
end;

class operator TASN1_Integer.Implicit(aValue: TBytes): TASN1_Integer;
begin
  if aValue = nil then aValue := [$00];
  Result.FValue := aValue;
end;

class operator TASN1_Integer.Initialize(out Dest: TASN1_Integer);
begin
  Dest.FDataType := Dest.DataType;
  Dest.FValue := [00];
  Dest.FIsPositive := True;
end;

function TASN1_BitString.DataSize: Cardinal;
begin
  Result := Length(FValue) + SizeOf(FUnusedBits);
end;

class function TASN1_BitString.DataType: TASN1_DataType;
begin
  Result := asnBitString;
end;

class operator TASN1_BitString.Implicit(aValue: TBytes): TASN1_BitString;
begin
  Result.FValue := aValue;
end;

class operator TASN1_BitString.Initialize(out Dest: TASN1_BitString);
begin
  Dest.FDataType := Dest.DataType;
  Dest.FValue := [];
  Dest.FUnusedBits := $00;
end;

class function TASN1_OctetString.DataType: TASN1_DataType;
begin
  Result := asnOctetString;
end;

class operator TASN1_OctetString.Initialize(out Dest: TASN1_OctetString);
begin
  Dest.FDataType := Dest.DataType;
end;

class function TASN1_Null.DataType: TASN1_DataType;
begin
  Result := asnNull;
end;

class operator TASN1_Null.Initialize(out Dest: TASN1_Null);
begin
  Dest.FDataType := Dest.DataType;
end;

class function TASN1_ObjectIdentifier.DataType: TASN1_DataType;
begin
  Result := asnObjectIdentifier;
end;

class operator TASN1_ObjectIdentifier.Implicit(
  aValue: string): TASN1_ObjectIdentifier;
begin
  Result.FValue := aValue;
end;

class operator TASN1_ObjectIdentifier.Initialize(out Dest:
    TASN1_ObjectIdentifier);
begin
  Dest.FDataType := Dest.DataType;
  Dest.FValue := '';
end;

procedure TASN1_Sequence.Add(const [ref] aField);
begin
  FValue.Add(aField);
end;

procedure TASN1_Sequence.AddNull;
begin
  var a: TASN1_Null;
  FValue.Add(a);
end;

class function TASN1_Sequence.DataType: TASN1_DataType;
begin
  Result := asnSequence;
end;

class operator TASN1_Sequence.Initialize(out Dest: TASN1_Sequence);
begin
  Dest.FDataType := Dest.DataType;
end;

class function TASN1_DER.Encode(const [ref] aField: TASN1_Boolean): TBytes;
begin
  var a: Byte;
  if aField.Value then a := $FF else a := $00;
  Result := aField.DataType.Tags + [SizeOf(a), a];
end;

class function TASN1_DER.Encode(const [ref] aField: TASN1_Integer): TBytes;
begin
  var a := aField.Value;
  var b := aField.DataSize;
  if aField.IsPositive and (a[0] >= $80{128}) then begin
    a := [$00] + a; // Leading Zero;
    Inc(b);
  end;
  Result := aField.DataType.Tags + EncodeLength(b) + a;
end;

class function TASN1_DER.Encode(const [ref] aField: TASN1_BitString): TBytes;
begin
  Result := aField.DataType.Tags + EncodeLength(aField.DataSize) + [aField.UnusedBits] + aField.Value;
end;

class function TASN1_DER.Encode(const [ref] aField: TASN1_Null): TBytes;
begin
  Result := [aField.DataType.Tag, $00];
end;

class function TASN1_DER.EncodeLength(aLen: Int64): TBytes;
begin
  if aLen < 0 then raise Exception.CreateResFmt(@SParamIsNegative, ['aLen']);

  if aLen < $80{128} then
    Result := [aLen]
  else begin
    Result := aLen.ToBigEndian;
    Result := [$80 + Length(Result)] + Result;
  end;
end;

class function TASN1_DER.Encode(const [ref] aField: TASN1_ObjectIdentifier): TBytes;
begin
  var a := aField.Value.Split(['.']);
  var b: TArray<Cardinal> := [];
  for var s in a do
    b := b + [s.ToInteger];

  // Encode first two nodes;
  var c: TBytes := [b[0] * $28{40} + b[1]];

  // Encode remaining nodes
  for var i := Low(b) + 2 to High(b) do begin
    if b[i] < $80{128} then
      c := c + [b[i]]
    else begin
      var d: TBytes := [];
      var e: Byte := $00;
      while b[i] > 0 do begin
        d := [(b[i] and $7F) or e] + d;
        b[i] := b[i] shr 7;
        e := $80;
      end;
      c := c + d;
    end;
  end;

  Result := aField.DataType.Tags + EncodeLength(Length(c)) + c;
end;

class function TASN1_DER.Encode(const [ref] aField: TASN1_Sequence): TBytes;
begin
  var a: TBytes := [];
  for var F in aField.Value.Fields do begin
    case F.DataType of
      asnBoolean:          a := a + Encode(F.GetValue<TASN1_Boolean>);
      asnInteger:          a := a + Encode(F.GetValue<TASN1_Integer>);
      asnBitString:        a := a + Encode(F.GetValue<TASN1_BitString>);
      asnNull:             a := a + Encode(F.GetValue<TASN1_Null>);
      asnObjectIdentifier: a := a + Encode(F.GetValue<TASN1_ObjectIdentifier>);
      asnSequence:         a := a + Encode(F.GetValue<TASN1_Sequence>);
    end;
  end;
  Result := aField.DataType.Tags + EncodeLength(Length(a)) + a;
end;

function TPEM.EndMarker: string;
begin
  Result := Hyphens + 'END ' + FLabel + Hyphens;
end;

class operator TPEM.Implicit(aValue: string): TPEM;
begin
  var iBegin1 := aValue.IndexOf(Hyphens + 'BEGIN ') + Length(Hyphens + 'BEGIN ');
  var iBegin2 := aValue.IndexOf(Hyphens, iBegin1 + 1);
  var iEndHyphen := aValue.IndexOf(Hyphens, iBegin2 + 1);
  Result.FLabel := aValue.Substring(iBegin1, iBegin2 - iBegin1);

  var iData := aValue.IndexOf(#10) + 1;
  var s := aValue.Substring(iData, iEndHyphen - iData);
  Result.FValue := TNetEncoding.Base64.DecodeStringToBytes(s);
end;

class operator TPEM.Initialize(out Dest: TPEM);
begin
  Dest.FLabel := '';
  Dest.FValue := [];
end;

function TPEM.BeginMarker: string;
begin
  Result := Hyphens + 'BEGIN ' + FLabel + Hyphens;
end;

procedure TPEM.SetValue(aLabel: string; aValue: TBytes);
begin
  FLabel := aLabel;
  FValue := aValue;
end;

class operator TPEM.Implicit(aValue: TPEM): string;
begin
  if Length(aValue.FValue) = 0 then Exit(string.Empty);

  var E := TNetEncoding.Base64 as TBase64Encoding;
  Result := aValue.BeginMarker + E.LineSeparator
          + E.EncodeBytesToString(aValue.FValue) + E.LineSeparator
          + aValue.EndMarker + E.LineSeparator;
end;

end.
