unit JWKS;

// RFC7517: JSON Web Key (JWK) - https://tools.ietf.org/html/rfc7517
// RFC7518: JSON Web Algorithms (JWA) - https://tools.ietf.org/html/rfc7517
// RFC8037: CFRG Elliptic Curve Diffie-Hellman - https://tools.ietf.org/html/rfc8037

interface

uses
  System.SysUtils;

type
  Tkty = record
  type
    Tkty_type = (unknown, EC, RSA, oct, OKP);
  strict private
    FValue: TKty_type;
    class var FValues: array[Tkty_type] of string;
    class function GetValues(Value: Tkty_type): string; static;
  public
    class constructor Create;
    class operator Implicit(Value: string): TKty;
    class operator Implicit(Value: Tkty): string;
    class operator Implicit(Value: Tkty): Tkty_type;
    class operator Implicit(Value: Tkty_type): Tkty;
    class operator Initialize(out Dest: Tkty);
    property Value: Tkty_type read FValue;
    class property Values[Value: Tkty_type]: string read GetValues; default;
  end;

  Talg = record
  type
    Talg_type = (none, ES256, ES384, ES512, HS256, HS384, HS512, PS256, PS384, PS512, RS256, RS384, RS512);
  strict private
    FValue: Talg_type;
    class var FValues: array[Talg_type] of string;
    class function GetValues(Value: Talg_type): string; static;
  public
    class constructor Create;
    class operator Equal(a: Talg; b: Talg_type): Boolean;
    class operator Implicit(Value: string): Talg;
    class operator Implicit(Value: Talg): string;
    class operator Implicit(Value: Talg): Talg_type;
    class operator Implicit(Value: Talg_type): Talg;
    class operator Initialize(out Dest: Talg);
    class property Values[Value: Talg_type]: string read GetValues; default;
  end;

  Tuse = record
  type
    Tuse_type = (sig, enc);
  strict private
    FValue: Tuse_type;
    class var FValues: array[Tuse_type] of string;
    class function GetValues(Value: Tuse_type): string; static;
  public
    class constructor Create;
    class operator Implicit(Value: string): Tuse;
    class operator Implicit(Value: Tuse): Tuse_type;
    class operator Implicit(Value: Tuse): string;
    class operator Implicit(Value: Tuse_type): Tuse;
    class property Values[Value: Tuse_type]: string read GetValues; default;
    property Value: Tuse_type read FValue;
  end;

  Tcrv = record
  type
    Tcrv_type = (P_256, P_384, P_521, X25519, X448);
  strict private
    FValue: Tcrv_type;
    class var FValues: array[Tcrv_type] of string;
    class function GetValues(Value: Tcrv_type): string; static;
  public
    class constructor Create;
    class operator Implicit(Value: string): Tcrv;
    class operator Implicit(Value: Tcrv): Tcrv_type;
    class operator Implicit(Value: Tcrv): string;
    class operator Implicit(Value: Tcrv_type): Tcrv;
    class property Values[Value: Tcrv_type]: string read GetValues; default;
  end;

  TJWK = record
  strict private
    Fkty: Tkty;
    Falg: Talg;
    use: Tuse;
    Fkid: string;
    // Parameters for RSA Keys
    Fn: TBytes;
    Fe: TBytes;
    Fd: TBytes;
    Fp: TBytes;
    Fq: TBytes;
    Fdp: TBytes;
    Fdq: TBytes;
    Fqi: TBytes;
    Foth: TBytes;
    // Parameters for Elliptic Curve Keys
    crv: Tcrv;
    Fx: TBytes;
    Fy: TBytes;
    // Parameters for Symmetric Keys
    Fk: TBytes;
  public
    class operator Implicit(Json: string): TJWK;
    property alg: Talg read Falg;
    property d: TBytes read Fd;
    property dp: TBytes read Fdp;
    property dq: TBytes read Fdq;
    property e: TBytes read Fe;
    property k: TBytes read Fk;
    property kid: string read Fkid;
    property kty: Tkty read Fkty;
    property n: TBytes read Fn;
    property oth: TBytes read Foth;
    property p: TBytes read Fp;
    property q: TBytes read Fq;
    property qi: TBytes read Fqi;
    property x: TBytes read Fx;
    property y: TBytes read Fy;
  end;

  TJWKS = record
  strict private
    FKeys: TArray<TJWK>;
    procedure Add(aKey: TJWK);
  public
    class operator Implicit(Json: string): TJWKS;
    class operator Initialize(out Dest: TJWKS);
    function Count: Integer;
    property Keys: TArray<TJWK> read FKeys;
  end;

implementation

uses
  System.Classes, System.JSON, System.NetEncoding, System.RTLConsts,
  System.NetEncoding.Base64Url;

class constructor Tkty.Create;
begin
  FValues[unknown] := '';
  FValues[EC]  := 'EC';
  FValues[RSA] := 'RSA';
  FValues[oct] := 'oct';
  FValues[OKP] := 'OKP';
end;

class function Tkty.GetValues(Value: Tkty_type): string;
begin
  Result := FValues[Value];
end;

class operator Tkty.Implicit(Value: string): TKty;
begin
  for var i := Low(FValues) to High(FValues) do
    if FValues[i] = Value then Exit(i);
  raise Exception.CreateResFmt(@SInvalidPropertyType, [Value]);
end;

class operator Tkty.Implicit(Value: Tkty): Tkty_type;
begin
  Result := Value.FValue;
end;

class operator Tkty.Implicit(Value: Tkty): string;
begin
  Result := FValues[Value.FValue];
end;

class operator Tkty.Implicit(Value: Tkty_type): Tkty;
begin
  Result.FValue := Value;
end;

class operator Tkty.Initialize(out Dest: Tkty);
begin
  Dest.FValue := unknown;
end;

class constructor Talg.Create;
begin
  FValues[none]  := 'none';
  FValues[ES256] := 'ES256';
  FValues[ES384] := 'ES384';
  FValues[ES512] := 'ES512';

  FValues[HS256] := 'HS256';
  FValues[HS384] := 'HS384';
  FValues[HS512] := 'HS512';

  FValues[PS256] := 'PS256';
  FValues[PS384] := 'PS384';
  FValues[PS512] := 'PS512';

  FValues[RS256] := 'RS256';
  FValues[RS384] := 'RS384';
  FValues[RS512] := 'RS512';
end;

class operator Talg.Equal(a: Talg; b: Talg_type): Boolean;
begin
  Result := a.FValue = b;
end;

class function Talg.GetValues(Value: Talg_type): string;
begin
  Result := FValues[Value];
end;

class operator Talg.Implicit(Value: string): Talg;
begin
  for var i := Low(FValues) to High(FValues) do
    if FValues[i] = Value then Exit(i);
  raise Exception.CreateResFmt(@SInvalidPropertyType, [Value]);
end;

class operator Talg.Implicit(Value: Talg): Talg_type;
begin
  Result := Value.FValue;
end;

class operator Talg.Implicit(Value: Talg): string;
begin
  Result := FValues[Value.FValue];
end;

class operator Talg.Implicit(Value: Talg_type): Talg;
begin
  Result.FValue := Value;
end;

class operator Talg.Initialize(out Dest: Talg);
begin
  Dest.FValue := none;
end;

class constructor Tuse.Create;
begin
  FValues[sig] := 'sig';
  FValues[enc] := 'enc';
end;

class function Tuse.GetValues(Value: Tuse_type): string;
begin
  Result := FValues[Value];
end;

class operator Tuse.Implicit(Value: string): Tuse;
begin
  for var i := Low(FValues) to High(FValues) do
    if FValues[i] = Value then Exit(i);
  raise Exception.CreateResFmt(@SInvalidPropertyType, [Value]);
end;

class operator Tuse.Implicit(Value: Tuse): string;
begin
  Result := FValues[Value.FValue];
end;

class operator Tuse.Implicit(Value: Tuse): Tuse_type;
begin
  Result := Value.FValue;
end;

class operator Tuse.Implicit(Value: Tuse_type): Tuse;
begin
  Result.FValue := Value;
end;

class constructor Tcrv.Create;
begin
  FValues[P_256]  := 'P-256';
  FValues[P_384]  := 'P-384';
  FValues[P_521]  := 'P-521';
  FValues[X25519] := 'X25519';
  FValues[X448]   := 'X448';
end;

class function Tcrv.GetValues(Value: Tcrv_type): string;
begin
  Result := FValues[Value];
end;

class operator Tcrv.Implicit(Value: string): Tcrv;
begin
  for var i := Low(FValues) to High(FValues) do
    if FValues[i] = Value then Exit(i);
  raise Exception.CreateResFmt(@SInvalidPropertyType, [Value]);
end;

class operator Tcrv.Implicit(Value: Tcrv): string;
begin
  Result := FValues[Value.FValue];
end;

class operator Tcrv.Implicit(Value: Tcrv): Tcrv_type;
begin
  Result := Value.FValue;
end;

class operator Tcrv.Implicit(Value: Tcrv_type): Tcrv;
begin
  Result.FValue := Value;
end;

class operator TJWK.Implicit(Json: string): TJWK;
begin
  var j := TJSONObject.ParseJSONValue(Json) as TJSONObject;
  try
    var s: string;

    if j.TryGetValue<string>('kty', s) then Result.Fkty := s else Exit;

    if j.TryGetValue<string>('use', s) then Result.use := s;
    if j.TryGetValue<string>('kid', s) then Result.Fkid := s;
    if j.TryGetValue<string>('alg', s) then Result.Falg := s;
    if j.TryGetValue<string>('crv', s) then Result.crv := s;

    // RSA
    if j.TryGetValue<string>('n',   s) then Result.Fn   := TNetEncoding.Base64Url.DecodeStringToBytes(s);
    if j.TryGetValue<string>('e',   s) then Result.Fe   := TNetEncoding.Base64Url.DecodeStringToBytes(s);
    if j.TryGetValue<string>('d',   s) then Result.Fd   := TNetEncoding.Base64Url.DecodeStringToBytes(s);
    if j.TryGetValue<string>('p',   s) then Result.Fp   := TNetEncoding.Base64Url.DecodeStringToBytes(s);
    if j.TryGetValue<string>('q',   s) then Result.Fq   := TNetEncoding.Base64Url.DecodeStringToBytes(s);
    if j.TryGetValue<string>('dp',  s) then Result.Fdp  := TNetEncoding.Base64Url.DecodeStringToBytes(s);
    if j.TryGetValue<string>('dq',  s) then Result.Fdq  := TNetEncoding.Base64Url.DecodeStringToBytes(s);
    if j.TryGetValue<string>('qi',  s) then Result.Fqi  := TNetEncoding.Base64Url.DecodeStringToBytes(s);
    if j.TryGetValue<string>('oth', s) then Result.Foth := TNetEncoding.Base64Url.DecodeStringToBytes(s);

    if (Result.Falg = none) and (Length(Result.Fn) > 0) then begin
      case Length(Result.fn) of
        256: Result.Falg := RS256;
        384: Result.Falg := RS384;
        512: Result.Falg := RS512;
      end;
    end;

    // EC
    if j.TryGetValue<string>('x',   s) then Result.Fx   := TNetEncoding.Base64Url.DecodeStringToBytes(s);
    if j.TryGetValue<string>('y',   s) then Result.Fy   := TNetEncoding.Base64Url.DecodeStringToBytes(s);

    // Symmetric Keys
    if j.TryGetValue<string>('k',   s) then Result.Fk   := TNetEncoding.Base64Url.DecodeStringToBytes(s);
  finally
    j.Free;
  end;
end;

procedure TJWKS.Add(aKey: TJWK);
begin
  if aKey.kty.Value = unknown then Exit;
  FKeys := FKeys + [aKey];
end;

function TJWKS.Count: Integer;
begin
  Result := Length(FKeys);
end;

class operator TJWKS.Implicit(Json: string): TJWKS;
begin
  var j := TJSONObject.ParseJSONValue(Json) as TJSONObject;
  try
    var A: TJSONArray;
    if not j.TryGetValue<TJSONArray>('keys', A) then Exit;

    for var i in A do begin
      var K: TJWK := i.ToJSON;
      Result.Add(K);
    end;
  finally
    j.Free;
  end;
end;

class operator TJWKS.Initialize(out Dest: TJWKS);
begin
  Dest.FKeys := [];
end;

end.
