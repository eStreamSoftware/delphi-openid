unit JWT.RS;

interface

uses System.SysUtils, JWT, ipcrsa, ipctypes;

type
  TJWTSigner_RSA = class abstract(TInterfacedObject, IJWTSigner)
  private
    FCipher: TipcRSA;
  protected
    class function HashAlgorithm: TipcrsaHashAlgorithms; virtual; abstract;
    class function UsePSS: Boolean; virtual; abstract;
    function Sign(Key, Input: TBytes): TBytes;
    function Validate(Key, Input, Signature: TBytes): Boolean;
  public
    procedure AfterConstruction; override;
    procedure BeforeDestruction; override;
  end;

  TJWTSigner_RSA256 = class(TJWTSigner_RSA)
  protected
    class function HashAlgorithm: TipcrsaHashAlgorithms; override;
    class function UsePSS: Boolean; override;
  end;

  TJWTSigner_RSA384 = class(TJWTSigner_RSA)
  protected
    class function HashAlgorithm: TipcrsaHashAlgorithms; override;
    class function UsePSS: Boolean; override;
  end;

  TJWTSigner_RSA512 = class(TJWTSigner_RSA)
  protected
    class function HashAlgorithm: TipcrsaHashAlgorithms; override;
    class function UsePSS: Boolean; override;
  end;

  TJWTSigner_RSAPSS256 = class(TJWTSigner_RSA)
  protected
    class function HashAlgorithm: TipcrsaHashAlgorithms; override;
    class function UsePSS: Boolean; override;
  end;

  TJWTSigner_RSAPSS384 = class(TJWTSigner_RSA)
  protected
    class function HashAlgorithm: TipcrsaHashAlgorithms; override;
    class function UsePSS: Boolean; override;
  end;

  TJWTSigner_RSAPSS512 = class(TJWTSigner_RSA)
  protected
    class function HashAlgorithm: TipcrsaHashAlgorithms; override;
    class function UsePSS: Boolean; override;
  end;

implementation

uses JWKS;

procedure TJWTSigner_RSA.AfterConstruction;
begin
  inherited;
  FCipher := TipcRSA.Create(nil);
end;

procedure TJWTSigner_RSA.BeforeDestruction;
begin
  FCipher.Free;
  inherited;
end;

function TJWTSigner_RSA.Sign(Key, Input: TBytes): TBytes;
begin
  FCipher.Reset;

  FCipher.UsePSS := UsePSS;
  FCipher.HashAlgorithm := HashAlgorithm;
  FCipher.Key.PrivateKey := TEncoding.ANSI.GetString(Key);
  FCipher.InputMessageB := Input;
  FCipher.Sign;
  Result := FCipher.HashSignatureB;
end;

function TJWTSigner_RSA.Validate(Key, Input, Signature: TBytes): Boolean;
begin
  FCipher.Reset;

  FCipher.UsePSS := UsePSS;
  FCipher.HashAlgorithm := HashAlgorithm;
  FCipher.SignerKey.PublicKey := TEncoding.ANSI.GetString(Key);
  FCipher.InputMessageB := Input;
  FCipher.HashSignatureB := Signature;
  Result := FCipher.VerifySignature;
end;

class function TJWTSigner_RSA256.HashAlgorithm: TipcrsaHashAlgorithms;
begin
  Result := rhaSHA256;
end;

class function TJWTSigner_RSA384.HashAlgorithm: TipcrsaHashAlgorithms;
begin
  Result := rhaSHA384;
end;

class function TJWTSigner_RSA384.UsePSS: Boolean;
begin
  Result := False;
end;

class function TJWTSigner_RSA512.HashAlgorithm: TipcrsaHashAlgorithms;
begin
  Result := rhaSHA512;
end;

class function TJWTSigner_RSA512.UsePSS: Boolean;
begin
  Result := False;
end;

class function TJWTSigner_RSA256.UsePSS: Boolean;
begin
  Result := False;
end;

class function TJWTSigner_RSAPSS256.HashAlgorithm: TipcrsaHashAlgorithms;
begin
  Result := rhaSHA256;
end;

class function TJWTSigner_RSAPSS256.UsePSS: Boolean;
begin
  Result := True;
end;

class function TJWTSigner_RSAPSS384.HashAlgorithm: TipcrsaHashAlgorithms;
begin
  Result := rhaSHA384;
end;

class function TJWTSigner_RSAPSS384.UsePSS: Boolean;
begin
  Result := True;
end;

class function TJWTSigner_RSAPSS512.HashAlgorithm: TipcrsaHashAlgorithms;
begin
  Result := rhaSHA512;
end;

class function TJWTSigner_RSAPSS512.UsePSS: Boolean;
begin
  Result := True;
end;

initialization
  TJWTSigner.Register(RS256, TJWTSigner_RSA256);
  TJWTSigner.Register(RS384, TJWTSigner_RSA384);
  TJWTSigner.Register(RS512, TJWTSigner_RSA512);
  TJWTSigner.Register(PS256, TJWTSigner_RSAPSS256);
  TJWTSigner.Register(PS384, TJWTSigner_RSAPSS384);
  TJWTSigner.Register(PS512, TJWTSigner_RSAPSS512);
end.
