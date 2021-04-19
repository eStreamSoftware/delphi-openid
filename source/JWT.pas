unit JWT;

interface

uses
  System.Classes, System.NetEncoding, System.SysUtils,
  JWKS;

type
  IJWTSigner = interface
  ['{6B5B4AFA-9E5E-41AA-B1BF-E497C8B3BA43}']
    function Sign(Key, Input: TBytes): TBytes;
    function Validate(Key, Input, Signature: TBytes): Boolean;
  end;

  TJWTSigner_None = class(TInterfacedObject, IJWTSigner)
  private
  protected
    function Sign(Key, Input: TBytes): TBytes;
    function Validate(Key, Input, Signature: TBytes): Boolean;
  end;

  TJWTSigner = class abstract
  strict private
    class var Algorithms: array[Talg.Talg_type] of TInterfacedClass;
    class constructor Create;
  public
    class function New(AlgType: Talg.Talg_type): IJWTSigner;
    class procedure Register(aAlgType: Talg.Talg_type; aClass: TInterfacedClass);
  end;

  Talg_helper = record helper for Talg
    class operator Implicit(Value: TAlg): IJWTSigner;
  end;

  TJWTValueType = (JWT_StringOrURI, JWT_NumericDate, JWT_Boolean);

  TJWTItem = record
  strict private
    FValueBoolean: Boolean;
    FValueNumeric: Int64;
    FValueString: string;
    FEnabled: Boolean;
  private
    procedure SetValueBoolean(const Value: Boolean);
    procedure SetValueNumeric(const Value: Int64);
    procedure SetValueString(const Value: string);
  public
    Name: string;
    ValueType: TJWTValueType;
    constructor Create(aName: string; aValueType: TJWTValueType);
    class operator Initialize(out Dest: TJWTItem);
    procedure Clear;
    property Enabled: Boolean read FEnabled;
    property ValueBoolean: Boolean read FValueBoolean write SetValueBoolean;
    property ValueNumeric: Int64 read FValueNumeric write SetValueNumeric;
    property ValueString: string read FValueString write SetValueString;
  end;

  THeader = record
  strict private
    typ: TJWTItem;
    FOriginalValue: string;
  public
    alg: TAlg;
    kid: TJWTItem;
    function ToBase64: string;
    class operator Implicit(Value: string): THeader;
    class operator Implicit(Value: THeader): string;
    class operator Initialize(out Dest: THeader);
  end;

  TClaims = record
  strict private
    FOriginalValue: string;
  public
    iss: TJWTItem;
    sub: TJWTItem;
    aud: TJWTItem;
    exp: TJWTItem;
    nbf: TJWTItem;
    iat: TJWTItem;
    jti: TJWTItem;
    Customs: TArray<TJWTItem>;
  public
    class operator Initialize(out Dest: TClaims);
    class operator Implicit(Value: string): TClaims;
    class operator Implicit(Value: TClaims): string;
    procedure Add(Item: TJWTItem); overload;
    procedure Add(aName: string; aValue: Boolean); overload;
    procedure Add(aName: string; aValue: string); overload;
    procedure Add(aName: string; aValue: Int64); overload;
    function ToBase64: string;
  end;

  TJWT = record
  strict private
    FIsValid: Boolean;
    Signature: string;
    FHeader: THeader;
    FClaims: TClaims;
    function GetToken: string;
    procedure SetValid;
    class function Sign(aHeader: THeader; aClaims: TClaims; aKey: string): string;
        overload; static;
  public
    constructor Create(aToken: string);
    function Sign(aAlgType: Talg.Talg_type; aKey: string): string; overload;
    function Validate(aKey: string): Boolean;
    class operator Implicit(Value: string): TJWT;
    class operator Implicit(Value: TJWT): Boolean;
    class operator Implicit(Value: TJWT): string;
    class operator Initialize(out Dest: TJWT);
    property Claims: TClaims read FClaims;
    property Header: THeader read FHeader;
  end;

implementation

uses
  System.JSON, System.RTLConsts,
  System.NetEncoding.Base64Url;

class constructor TJWTSigner.Create;
begin
  FillChar(Algorithms, Length(Algorithms), 0);
end;

class function TJWTSigner.New(AlgType: Talg.Talg_type): IJWTSigner;
begin
  var c := Algorithms[AlgType];
  if c = nil then
    raise Exception.CreateResFmt(@SInvalidPropertyType, [Integer(AlgType).ToString]);
  Result := c.Create as IJWTSigner;
end;

class procedure TJWTSigner.Register(aAlgType: Talg.Talg_type;
  aClass: TInterfacedClass);
begin
  Algorithms[aAlgType] := aClass;
end;

class operator Talg_helper.Implicit(Value: TAlg): IJWTSigner;
begin
  Result := TJWTSigner.New(Value);
end;

procedure TJWTItem.Clear;
begin
  FEnabled := False;
end;

constructor TJWTItem.Create(aName: string; aValueType: TJWTValueType);
begin
  Clear;
  Name := aName;
  ValueType := aValueType;
end;

class operator TJWTItem.Initialize(out Dest: TJWTItem);
begin
  Dest.Clear;
end;

procedure TJWTItem.SetValueBoolean(const Value: Boolean);
begin
  if ValueType <> JWT_Boolean then raise Exception.CreateResFmt(@SInvalidPropertyType, [BoolToStr(Value)]);
  FValueBoolean := Value;
  FEnabled := True;
end;

procedure TJWTItem.SetValueNumeric(const Value: Int64);
begin
  if ValueType <> JWT_NumericDate then raise Exception.CreateResFmt(@SInvalidPropertyType, [Value.ToString]);
  FValueNumeric := Value;
  FEnabled := True;
end;

procedure TJWTItem.SetValueString(const Value: string);
begin
  if ValueType <> JWT_StringOrURI then raise Exception.CreateResFmt(@SInvalidPropertyType, [Value]);
  FValueString := Value;
  FEnabled := True;
end;

function THeader.ToBase64: string;
begin
  Result := TNetEncoding.Base64Url.Encode(Self);
end;

class operator THeader.Implicit(Value: string): THeader;
begin
  Result.FOriginalValue := Value;
  var J := TJSONObject.ParseJSONValue(Value, True) as TJSONObject;
  try
    for var o in J do begin
           if (o.JsonString.Value = Result.typ.Name) and (o.JsonValue.Value <> Result.typ.ValueString) then raise Exception.CreateResFmt(@SInvalidPropertyType, [o.JsonValue.Value])
      else if o.JsonString.Value = 'alg' then Result.alg := o.JsonValue.Value
      else if o.JsonString.Value = Result.kid.Name then Result.kid.ValueString  := o.JsonValue.Value
    end;
  finally
    J.Free;
  end;
end;

class operator THeader.Implicit(Value: THeader): string;
begin
  if Value.FOriginalValue <> '' then Exit(Value.FOriginalValue);

  var J := TJSONObject.Create;
  try
    J.AddPair(Value.typ.Name, Value.typ.ValueString);
    J.AddPair('alg', Value.alg);
    if Value.kid.Enabled then J.AddPair(Value.kid.Name, Value.kid.ValueString);
    Result := J.ToString;
  finally
    J.Free;
  end;
end;

class operator THeader.Initialize(out Dest: THeader);
begin
  with Dest do begin
    typ := TJWTItem.Create('typ', JWT_StringOrURI);
    typ.ValueString := 'JWT';
    kid := TJWTItem.Create('kid', JWT_StringOrURI);
    FOriginalValue := '';
  end;
end;

class operator TClaims.Implicit(Value: string): TClaims;
begin
  Result.FOriginalValue := Value;
  var t: TJWTItem;
  var J := TJSONObject.ParseJSONValue(Value) as TJSONObject;
  try
    for var o in J do begin
           if o.JsonString.Value = Result.iss.Name then Result.iss.ValueString  := o.JsonValue.Value
      else if o.JsonString.Value = Result.sub.Name then Result.sub.ValueString  := o.JsonValue.Value
      else if o.JsonString.Value = Result.aud.Name then Result.aud.ValueString  := o.JsonValue.Value
      else if o.JsonString.Value = Result.exp.Name then Result.exp.ValueNumeric := o.JsonValue.AsType<Int64>
      else if o.JsonString.Value = Result.nbf.Name then Result.nbf.ValueNumeric := o.JsonValue.AsType<Int64>
      else if o.JsonString.Value = Result.iat.Name then Result.iat.ValueNumeric := o.JsonValue.AsType<Int64>
      else if o.JsonString.Value = Result.jti.Name then Result.jti.ValueString  := o.JsonValue.Value
      else begin
        if o.JsonValue is TJSONNumber then begin
          t := TJWTItem.Create(o.JsonString.Value, JWT_NumericDate);
          t.ValueNumeric := o.JsonValue.GetValue<Int64>;
        end else if o.JsonValue is TJSONString then begin
          t := TJWTItem.Create(o.JsonString.Value, JWT_StringOrURI);
          t.ValueString := o.JsonValue.Value;
        end else if o.JsonValue is TJSONBool then begin
          t := TJWTItem.Create(o.JsonString.Value, JWT_Boolean);
          t.ValueBoolean := o.JsonValue.GetValue<Boolean>;
        end else if (o.JsonValue is TJSONObject) or (o.JsonValue is TJSONArray) then begin
          t := TJWTItem.Create(o.JsonString.Value, JWT_StringOrURI);
          t.ValueString := o.JsonValue.ToJSON;
        end else
          raise Exception.CreateResFmt(@SInvalidRegType, [o.JsonValue.ClassName]);
        Result.Add(t);
      end;
    end;
  finally
    J.Free;
  end;
end;

procedure TClaims.Add(Item: TJWTItem);
begin
  Customs := Customs + [Item];
end;

procedure TClaims.Add(aName: string; aValue: Boolean);
begin
  var i := TJWTItem.Create(aName, JWT_Boolean);
  i.ValueBoolean := aValue;
  Add(i);
end;

procedure TClaims.Add(aName: string; aValue: Int64);
begin
  var i := TJWTItem.Create(aName, JWT_NumericDate);
  i.ValueNumeric := aValue;
  Add(i);
end;

procedure TClaims.Add(aName, aValue: string);
begin
  var i := TJWTItem.Create(aName, JWT_StringOrURI);
  i.ValueString := aValue;
  Add(i);
end;

class operator TClaims.Implicit(Value: TClaims): string;
begin
  if Value.FOriginalValue <> '' then Exit(Value.FOriginalValue);

  var J := TJSONObject.Create;
  try
    if Value.iss.Enabled then J.AddPair(Value.iss.Name, Value.iss.ValueString);
    if Value.sub.Enabled then J.AddPair(Value.sub.Name, Value.sub.ValueString);
    if Value.aud.Enabled then J.AddPair(Value.aud.Name, Value.aud.ValueString);
    if Value.exp.Enabled then J.AddPair(Value.exp.Name, TJSONNumber.Create(Value.exp.ValueNumeric));
    if Value.nbf.Enabled then J.AddPair(Value.nbf.Name, TJSONNumber.Create(Value.nbf.ValueNumeric));
    if Value.iat.Enabled then J.AddPair(Value.iat.Name, TJSONNumber.Create(Value.iat.ValueNumeric));
    if Value.jti.Enabled then J.AddPair(Value.jti.Name, Value.jti.ValueString);

    for var o in Value.Customs do begin
      if o.Enabled then begin
        case o.ValueType of
              JWT_Boolean: J.AddPair(o.Name, TJSONBool.Create(o.ValueBoolean));
          JWT_NumericDate: J.AddPair(o.Name, TJSONNumber.Create(o.ValueNumeric));
          JWT_StringOrURI: J.AddPair(o.Name, o.ValueString);
        end;
      end;
    end;

    Result := J.ToString;
  finally
    J.Free;
  end;
end;

class operator TClaims.Initialize(out Dest: TClaims);
begin
  with Dest do begin
    iss := TJWTItem.Create('iss', JWT_StringOrURI);
    sub := TJWTItem.Create('sub', JWT_StringOrURI);
    aud := TJWTItem.Create('aud', JWT_StringOrURI);
    exp := TJWTItem.Create('exp', JWT_NumericDate);
    nbf := TJWTItem.Create('nbf', JWT_NumericDate);
    iat := TJWTItem.Create('iat', JWT_NumericDate);
    jti := TJWTItem.Create('jti', JWT_StringOrURI);
    Customs := [];
    FOriginalValue := '';
  end;
end;

function TClaims.ToBase64: string;
begin
  Result := TNetEncoding.Base64Url.Encode(Self);
end;

constructor TJWT.Create(aToken: string);
begin
  var A := aToken.Split(['.']);
  if Length(A) <> 3 then raise Exception.CreateResFmt(@sInvalidInitialCount, [Length(A)]);
  FHeader := TNetEncoding.Base64Url.Decode(A[0]);
  FClaims := TNetEncoding.Base64Url.Decode(A[1]);
  Signature := A[2];
end;

function TJWT.GetToken: string;
begin
  if not FIsValid then raise Exception.Create('Invalid signature');
  Result := Header.ToBase64 + '.' + Claims.ToBase64 + '.' + Signature;
end;

procedure TJWT.SetValid;
begin
  FIsValid := True;
end;

function TJWT.Sign(aAlgType: Talg.Talg_type; aKey: string): string;
begin
  FHeader.alg := aAlgType;
  Signature := Sign(FHeader, Claims, aKey);
  SetValid;
  Result := GetToken;
end;

class function TJWT.Sign(aHeader: THeader; aClaims: TClaims; aKey: string):
    string;
begin
  var i := aHeader.ToBase64 + '.' + aClaims.ToBase64;
  var o: IJWTSigner := aHeader.alg;
  Result := TNetEncoding.Base64Url.EncodeBytesToString(o.Sign(TEncoding.ANSI.GetBytes(aKey), TEncoding.ANSI.GetBytes(i)));
end;

function TJWT.Validate(aKey: string): Boolean;
begin
  var i := Header.ToBase64 + '.' + Claims.ToBase64;
  var o: IJWTSigner := Header.alg;
  FIsValid := o.Validate(TEncoding.ANSI.GetBytes(aKey), TEncoding.ANSI.GetBytes(i), TNetEncoding.Base64Url.DecodeStringToBytes(Signature));
  Result := FIsValid;
end;

class operator TJWT.Implicit(Value: string): TJWT;
begin
  Result := TJWT.Create(Value);
end;

class operator TJWT.Implicit(Value: TJWT): Boolean;
begin
  Result := Value.FIsValid;
end;

class operator TJWT.Implicit(Value: TJWT): string;
begin
  Result := Value.GetToken;
end;

class operator TJWT.Initialize(out Dest: TJWT);
begin
  Dest.FIsValid := False;
end;

function TJWTSigner_None.Sign(Key, Input: TBytes): TBytes;
begin
  Result := nil;
end;

function TJWTSigner_None.Validate(Key, Input, Signature: TBytes): Boolean;
begin
  Result := True;
end;

initialization
  TJWTSigner.Register(none, TJWTSigner_None);
end.
