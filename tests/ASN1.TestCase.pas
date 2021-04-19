unit ASN1.TestCase;

interface

uses
  TestFramework;

(* Online encoder / decoder:
  1. https://asn1.io/asn1playground/
  2. https://lapo.it/asn1js/
  3. https://www.mobilefish.com/services/big_number/big_number.php
*)

type
  TASN1_TestCase = class(TTestCase)
  public
    class constructor Create;
  published
    procedure Test_Boolean;
    procedure Test_Integer;
    procedure Test_BitString;
    procedure Test_Null;
    procedure Test_ObjectIdentifier;
    procedure Test_Sequence;
    procedure Test_PEM;
    procedure DER_EncodeLength;
    procedure X509_RSA;
    procedure X509_EC;
  end;

implementation

uses
  System.SysUtils, System.NetEncoding,
  ASN1, ASN1.X509, System.NetEncoding.Base64Url;

class constructor TASN1_TestCase.Create;
begin
  RegisterTest(Suite);
end;

procedure TASN1_TestCase.DER_EncodeLength;
begin
  for var i := 0 to 127 do
    CheckEqualsMem(TBytes.Create(i), TASN1_DER.EncodeLength(i), 1);

  CheckEqualsMem(TBytes.Create($81, $80), TASN1_DER.EncodeLength(128), 2);
  CheckEqualsMem(TBytes.Create($82, $01, $01), TASN1_DER.EncodeLength(257), 2);
  CheckEqualsMem(TBytes.Create($82, $13, $46), TASN1_DER.EncodeLength(4934), 2);

  StartExpectingException(Exception);
  TASN1_DER.EncodeLength(-1);
end;

procedure TASN1_TestCase.Test_BitString;
begin
  var a: TASN1_BitString;
  CheckTrue(asnBitString = a.DataType);
  CheckEquals(0, Length(a.Value));

  var c := TBytes.Create(
    $47, $eb, $99, $5a, $df, $9e, $70, $0d, $fb, $a7, $31, $32, $c1, $5f, $5c, $24
  , $c2, $e0, $bf, $c6, $24, $af, $15, $66, $0e, $b8, $6a, $2e, $ab, $2b, $c4, $97
  , $1f, $e3, $cb, $dc, $63, $a5, $25, $ec, $c7, $b4, $28, $61, $66, $36, $a1, $31
  , $1b, $bf, $dd, $d0, $fc, $bf, $17, $94, $90, $1d, $e5, $5e, $c7, $11, $5e, $c9
  , $55, $9f, $eb, $a3, $3e, $14, $c7, $99, $a6, $cb, $ba, $a1, $46, $0f, $39, $d4
  , $44, $c4, $c8, $4b, $76, $0e, $20, $5d, $6d, $a9, $34, $9e, $d4, $d5, $87, $42
  , $eb, $24, $26, $51, $14, $90, $b4, $0f, $06, $5e, $52, $88, $32, $7a, $95, $20
  , $a0, $fd, $f7, $e5, $7d, $60, $dd, $72, $68, $9b, $f5, $7b, $05, $8f, $6d, $1e
  );

  a := c;
  CheckEqualsMem(TBytes.Create($03, $81, $81, $00) + c, TASN1_DER.Encode(a), 4 + Length(c));
end;

procedure TASN1_TestCase.Test_Boolean;
begin
  var a: TASN1_Boolean;
  CheckTrue(asnBoolean = a.DataType);

  a := False;
  CheckFalse(a);
  CheckEqualsMem(TBytes.Create($01, $01, $00), TASN1_DER.Encode(a), 3);

  a := True;
  CheckTrue(a);
  CheckEqualsMem(TBytes.Create($01, $01, $FF), TASN1_DER.Encode(a), 3);
end;

procedure TASN1_TestCase.Test_Integer;
begin
  var a: TASN1_Integer;
  CheckTrue(asnInteger = a.DataType);
  CheckEquals(1, a.DataSize);

  CheckEqualsMem(TBytes.Create($02, $01, $00), TASN1_DER.Encode(a), 3);

  a := 127;
  CheckEqualsMem(TBytes.Create($02, $01, $7F), TASN1_DER.Encode(a), 3);

  a := 128;
  CheckEqualsMem(TBytes.Create($02, $02, $00, $80), TASN1_DER.Encode(a), 4);

  a := High(Int64); // 9223372036854775807
  CheckEqualsMem(TBytes.Create($02, $08, $7F, $FF, $FF, $FF, $FF, $FF, $FF, $FF), TASN1_DER.Encode(a), 10);

  var c := TBytes.Create(
    $0F, $FD, $5B, $25, $87, $A7, $01, $73, $49, $10, $A6, $F5, $20, $B4, $40, $EE,
    $1B, $03, $EF, $FC, $91, $4A, $1C, $46, $32, $84, $A1, $8E, $4D, $F3, $6D, $9A,
    $C7, $61, $53, $21, $05, $04, $52, $C3, $1D, $E1, $7B, $1E, $7D, $8A, $66, $46,
    $8A, $48, $8E, $5C, $A3, $BE, $38, $88, $B8, $AF, $90, $76, $67, $04, $D6, $F3,
    $96, $B8, $74, $75, $AB, $C9, $86, $FB, $A2, $F0, $3D, $D9, $02, $8F, $47, $1F,
    $8D, $79, $74, $7E, $FB, $C1, $99, $15, $8E, $21, $19, $93, $1F, $90, $BD, $98,
    $6F, $50, $D5, $E5, $E7, $EB, $00, $1B, $51, $E3, $B7, $25, $A5, $01, $C2, $A0,
    $17, $88, $A9, $93, $5E, $24, $3D, $11, $61, $EF, $7B, $F1, $4B, $AC, $CF, $F1,
    $96, $CE, $3F, $0A, $D2
  );
  a := c;
  CheckEqualsMem(TBytes.Create($02, $81, $85) + c, TASN1_DER.Encode(a), Length(c) + 3);

  a := -1;
  CheckEqualsMem(TBytes.Create($02, $01, $FF), TASN1_DER.Encode(a), 3);

  a := -2;
  CheckEqualsMem(TBytes.Create($02, $01, $FE), TASN1_DER.Encode(a), 3);

  a := -127;
  CheckEqualsMem(TBytes.Create($02, $01, $81), TASN1_DER.Encode(a), 3);

  a := -128;
  CheckEqualsMem(TBytes.Create($02, $01, $80), TASN1_DER.Encode(a), 3);

  a := 65537;
  CheckEqualsMem(TBytes.Create($02, $03, $01, $00, $01), TASN1_DER.Encode(a), 5);
end;

procedure TASN1_TestCase.Test_Null;
begin
  var a: TASN1_Null;
  CheckTrue(asnNull = a.DataType);
  CheckEqualsMem(TBytes.Create($05, $00), TASN1_DER.Encode(a), 2);
end;

procedure TASN1_TestCase.Test_ObjectIdentifier;
begin
  var a: TASN1_ObjectIdentifier;
  CheckTrue(asnObjectIdentifier = a.DataType);

  a := '1.2.840.113549.1.1.1';
  CheckEqualsMem(TBytes.Create($06, $09, $2a, $86, $48, $86, $f7, $0d, $01, $01, $01), TASN1_DER.Encode(a), 11);

  a := '1.3.6.1.4.1.311.21.20';
  CheckEqualsMem(TBytes.Create($06, $09, $2b, $06, $01, $04, $01, $82, $37, $15, $14), TASN1_DER.Encode(a), 11);

  a := '1.2.840.10045.2.1';
  CheckEqualsMem(TBytes.Create($06, $07, $2a, $86, $48, $ce, $3d, $02, $01), TASN1_DER.Encode(a), 9);
end;

procedure TASN1_TestCase.Test_PEM;
begin
  var a := '-----BEGIN PUBLIC KEY-----' + sLineBreak
         + 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEg9JCShMJJ2ZJ44+xDqizdxZd+djtmb/HTnI6ckkx' + sLineBreak
         + 'o0wvcEs52f8NS967o3RWL0zuuh+gF9E9DlQ5wDgMIRqIEA==' + sLineBreak
         + '-----END PUBLIC KEY-----' + sLineBreak;

  var D := TBytes.Create(
    $30, $59, $30, $13, $06, $07, $2a, $86, $48, $ce, $3d, $02, $01, $06, $08, $2a
  , $86, $48, $ce, $3d, $03, $01, $07, $03, $42, $00, $04, $83, $d2, $42, $4a, $13
  , $09, $27, $66, $49, $e3, $8f, $b1, $0e, $a8, $b3, $77, $16, $5d, $f9, $d8, $ed
  , $99, $bf, $c7, $4e, $72, $3a, $72, $49, $31, $a3, $4c, $2f, $70, $4b, $39, $d9
  , $ff, $0d, $4b, $de, $bb, $a3, $74, $56, $2f, $4c, $ee, $ba, $1f, $a0, $17, $d1
  , $3d, $0e, $54, $39, $c0, $38, $0c, $21, $1a, $88, $10
  );

  var P: TPEM;
  P.SetValue('PUBLIC KEY', D);
  CheckEquals(a, P);

  P := a;
  CheckEquals(a, P);
end;

procedure TASN1_TestCase.Test_Sequence;
begin
  var a: TASN1_Sequence;
  CheckTrue(asnSequence = a.DataType);

  var c := TBytes.Create($30, $0B, $02, $03, $01, $00, $01, $02, $01, $00, $01, $01, $FF);

  a.Add(TASN1_Integer(65537));
  a.Add(TASN1_Integer(0));
  a.Add(TASN1_Boolean(True));
  CheckEqualsMem(c, TASN1_DER.Encode(a), Length(c));
end;

procedure TASN1_TestCase.X509_EC;
begin
  var a := TBytes.Create(
    $30, $59,
    $30, $13,
    $06, $07,
    $2a, $86, $48, $ce, $3d, $02, $01,
    $06, $08,
    $2a, $86, $48, $ce, $3d, $03, $01, $07,
    $03, $42,
    $00,
    $04, $83, $d2, $42, $4a, $13, $09, $27, $66, $49, $e3, $8f, $b1, $0e, $a8, $b3,
    $77, $16, $5d, $f9, $d8, $ed, $99, $bf, $c7, $4e, $72, $3a, $72, $49, $31, $a3,
    $4c, $2f, $70, $4b, $39, $d9, $ff, $0d, $4b, $de, $bb, $a3, $74, $56, $2f, $4c,
    $ee, $ba, $1f, $a0, $17, $d1, $3d, $0e, $54, $39, $c0, $38, $0c, $21, $1a, $88,
    $10
  );

  var b := X509_PublicKeyInfo_ECC.Create(
    TNetEncoding.Base64Url.DecodeStringToBytes('g9JCShMJJ2ZJ44-xDqizdxZd-djtmb_HTnI6ckkxo0w'),
    TNetEncoding.Base64Url.DecodeStringToBytes('L3BLOdn/DUveu6N0Vi9M7rofoBfRPQ5UOcA4DCEaiBA')
  );
  CheckEqualsMem(a, TASN1_DER.Encode(b), Length(a));
end;

procedure TASN1_TestCase.X509_RSA;
begin
  var a := TBytes.Create(
    $30, $82, $01, $22,
    $30, $0d,
    $06, $09,
    $2a, $86, $48, $86, $f7, $0d, $01, $01, $01,
    $05, $00,
    $03, $82, $01, $0f,
    $00,
    $30, $82, $01, $0a,
    $02, $82, $01, $01,
    $00,
    $c5, $89, $b5, $61, $07, $17, $99, $50, $34, $66, $87, $af, $ce, $01, $a5, $14,
    $a5, $33, $14, $f8, $81, $95, $b5, $5e, $99, $31, $39, $66, $f5, $a9, $fa, $7f,
    $b8, $b5, $08, $cc, $88, $b9, $df, $31, $5a, $b7, $36, $6f, $63, $ed, $e7, $12,
    $d9, $31, $cf, $ea, $ff, $7d, $76, $cf, $df, $23, $c9, $28, $f9, $ac, $f8, $9e,
    $f3, $b5, $2a, $33, $59, $4c, $42, $1d, $8f, $f9, $ef, $09, $b2, $6f, $6a, $9d,
    $0e, $fb, $89, $d1, $1a, $0e, $9a, $44, $53, $11, $0a, $aa, $e6, $d4, $dd, $14,
    $ef, $19, $36, $70, $83, $8e, $eb, $56, $a9, $d2, $42, $e7, $c9, $eb, $84, $a3,
    $65, $8b, $84, $ec, $9c, $75, $3a, $83, $12, $1e, $9f, $0d, $8e, $e5, $1f, $05,
    $98, $7b, $59, $3d, $56, $77, $ee, $e7, $5a, $1d, $3f, $1c, $ce, $5c, $61, $b9,
    $76, $74, $19, $2f, $cb, $32, $bb, $fe, $b8, $6c, $d2, $f7, $46, $25, $0b, $ff,
    $f2, $c7, $af, $7d, $46, $66, $ec, $6b, $a4, $18, $3e, $6d, $1b, $bb, $31, $ab,
    $98, $a9, $5e, $80, $d7, $b8, $ed, $46, $24, $b1, $67, $4d, $8e, $65, $1b, $77,
    $6a, $99, $87, $07, $2f, $73, $a6, $ab, $28, $ac, $30, $9e, $39, $7c, $02, $86,
    $a2, $9a, $2e, $e6, $82, $34, $91, $47, $a6, $c6, $00, $68, $cf, $7b, $38, $37,
    $11, $cf, $61, $9a, $14, $8b, $47, $ea, $e5, $30, $e0, $aa, $6b, $a8, $6a, $a1,
    $ba, $59, $3c, $54, $80, $56, $8e, $89, $ea, $43, $36, $36, $74, $2f, $69, $cb,
    $02, $03,
    $01, $00, $01
  );

  var b := X509_PublicKeyInfo_Rsa.Create(
    TNetEncoding.Base64Url.DecodeStringToBytes(
      'xYm1YQcXmVA0ZoevzgGlFKUzFPiBlbVemTE5ZvWp-n-4tQjMiLnfMVq3Nm9j7ecS2'
    + 'THP6v99ds_fI8ko-az4nvO1KjNZTEIdj_nvCbJvap0O-4nRGg6aRFMRCqrm1N0U7x'
    + 'k2cIOO61ap0kLnyeuEo2WLhOycdTqDEh6fDY7lHwWYe1k9Vnfu51odPxzOXGG5dnQ'
    + 'ZL8syu_64bNL3RiUL__LHr31GZuxrpBg-bRu7MauYqV6A17jtRiSxZ02OZRt3apmH'
    + 'By9zpqsorDCeOXwChqKaLuaCNJFHpsYAaM97ODcRz2GaFItH6uUw4KprqGqhulk8V'
    + 'IBWjonqQzY2dC9pyw'
    ),
    TNetEncoding.Base64Url.DecodeStringToBytes('AQAB')
  );
  CheckEqualsMem(a, TASN1_DER.Encode(b), Length(a));
end;

initialization
  TASN1_TestCase.ClassName;
end.
