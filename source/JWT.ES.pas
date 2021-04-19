unit JWT.ES;

interface

uses System.SysUtils, JWT, ipcecc, ipctypes;

type
  TJWTSigner_ECC = class abstract(TInterfacedObject, IJWTSigner)
  private
    FCipher: TipcECC;
  protected
    class function HashAlgorithm: TipcECCHashAlgorithms; virtual; abstract;
    class function UsePSS: Boolean; virtual; abstract;
    function Sign(Key, Input: TBytes): TBytes;
    function Validate(Key, Input, Signature: TBytes): Boolean;
  public
    procedure AfterConstruction; override;
    procedure BeforeDestruction; override;
  end;

  TJWTSigner_ES256 = class(TJWTSigner_ECC)
  protected
    class function HashAlgorithm: TipcECCHashAlgorithms; override;
  end;

  TJWTSigner_ES384 = class(TJWTSigner_ECC)
  protected
    class function HashAlgorithm: TipcECCHashAlgorithms; override;
  end;

  TJWTSigner_ES512 = class(TJWTSigner_ECC)
  protected
    class function HashAlgorithm: TipcECCHashAlgorithms; override;
  end;

implementation

uses JWKS;

procedure TJWTSigner_ECC.AfterConstruction;
begin
  inherited;
  FCipher := TipcECC.Create(nil);
end;

procedure TJWTSigner_ECC.BeforeDestruction;
begin
  FCipher.Free;
  inherited;
end;

function TJWTSigner_ECC.Sign(Key, Input: TBytes): TBytes;
begin
  FCipher.Reset;

  FCipher.HashAlgorithm := HashAlgorithm;
  FCipher.Key.PrivateKey := TEncoding.ANSI.GetString(Key);
  FCipher.InputMessageB := Input;
  FCipher.Sign;
  Result := FCipher.HashSignatureB;
end;

function TJWTSigner_ECC.Validate(Key, Input, Signature: TBytes): Boolean;
begin
  FCipher.Reset;

  FCipher.HashAlgorithm := HashAlgorithm;
  FCipher.SignerKey.PublicKey := TEncoding.ANSI.GetString(Key);
  FCipher.InputMessageB := Input;
  FCipher.HashSignatureB := Signature;
  Result := FCipher.VerifySignature;
end;

class function TJWTSigner_ES256.HashAlgorithm: TipcECCHashAlgorithms;
begin
  Result := ehaSHA256;
end;

class function TJWTSigner_ES384.HashAlgorithm: TipcECCHashAlgorithms;
begin
  Result := ehaSHA384;
end;

class function TJWTSigner_ES512.HashAlgorithm: TipcECCHashAlgorithms;
begin
  Result := ehaSHA512;
end;

initialization
  TJWTSigner.Register(ES256, TJWTSigner_ES256);
  TJWTSigner.Register(ES384, TJWTSigner_ES384);
  TJWTSigner.Register(ES512, TJWTSigner_ES512);
end.
