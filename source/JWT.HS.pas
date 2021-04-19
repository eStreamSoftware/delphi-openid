unit JWT.HS;

interface

uses
  System.Hash, System.SysUtils,
  JWT;

type
  TJWTSigner_SHA2 = class abstract(TInterfacedObject, IJWTSigner)
  protected
    class function GetSHA2Version: THashSHA2.TSHA2Version; virtual; abstract;
    function Sign(Key, Input: TBytes): TBytes;
    function Validate(Key, Input, Signature: TBytes): Boolean;
  end;

  TJWTSigner_HS256 = class(TJWTSigner_SHA2)
  protected
    class function GetSHA2Version: THashSHA2.TSHA2Version; override;
  end;

  TJWTSigner_HS384 = class(TJWTSigner_SHA2)
  protected
    class function GetSHA2Version: THashSHA2.TSHA2Version; override;
  end;

  TJWTSigner_HS512 = class(TJWTSigner_SHA2)
  protected
    class function GetSHA2Version: THashSHA2.TSHA2Version; override;
  end;

implementation

uses JWKS;

function TJWTSigner_SHA2.Sign(Key, Input: TBytes): TBytes;
begin
  Result := THashSHA2.GetHMACAsBytes(Input, Key, GetSHA2Version);
end;

function TJWTSigner_SHA2.Validate(Key, Input, Signature: TBytes): Boolean;
begin
  var R := Sign(Key, Input);
  Result := Length(R) = Length(Signature);
  if Result then begin
    for var i := Low(R) to High(R) do begin
      Result := R[i] = Signature[i];
      if not Result then Exit;
    end;
  end;
end;

class function TJWTSigner_HS256.GetSHA2Version: THashSHA2.TSHA2Version;
begin
  Result := THashSHA2.TSHA2Version.SHA256;
end;

class function TJWTSigner_HS384.GetSHA2Version: THashSHA2.TSHA2Version;
begin
  Result := THashSHA2.TSHA2Version.SHA384;
end;

class function TJWTSigner_HS512.GetSHA2Version: THashSHA2.TSHA2Version;
begin
  Result := THashSHA2.TSHA2Version.SHA512;
end;

initialization
  TJWTSigner.Register(HS256, TJWTSigner_HS256);
  TJWTSigner.Register(HS384, TJWTSigner_HS384);
  TJWTSigner.Register(HS512, TJWTSigner_HS512);
end.
