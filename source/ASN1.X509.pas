unit ASN1.X509;

interface

uses
  ASN1;

type
  X509_PublicKeyInfo_RSA = record
  strict private
    modulus: TASN1_Integer;
    publicExponent: TASN1_Integer;
  public
    constructor Create(aModulus, apublicExponent: TASN1_Integer);
    class function &Label: string; static;
    function Value: TASN1_Sequence;
    class operator Implicit(aValue: X509_PublicKeyInfo_RSA): TASN1_Sequence;
  end;

  X509_PublicKeyInfo_ECC = record
  strict private
    x: TASN1_Integer;
    y: TASN1_Integer;
  public
    constructor Create(ax, ay: TASN1_Integer);
    class function &Label: string; static;
    class operator Implicit(aValue: X509_PublicKeyInfo_ECC): TASN1_Sequence;
  end;

implementation

constructor X509_PublicKeyInfo_RSA.Create(aModulus, apublicExponent: TASN1_Integer);
begin
  modulus := aModulus;
  publicExponent := apublicExponent;
end;

class function X509_PublicKeyInfo_RSA.&Label: string;
begin
  Result := 'PUBLIC KEY';
end;

function X509_PublicKeyInfo_RSA.Value: TASN1_Sequence;
begin
  Result := Self;
end;

class operator X509_PublicKeyInfo_RSA.Implicit(aValue: X509_PublicKeyInfo_RSA):
    TASN1_Sequence;
(* rfc2459
  SubjectPublicKeyInfo ::= SEQUENCE {
    SEQUENCE {
      rsaEncryption OBJECT IDENTIFIER ::= {
        iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-1(1) 1
      },
      NULL
    },
    subjectPublicKey BIT STRING {
      RSAPublicKey ::= SEQUENCE {
        modulus         INTEGER, -- n
        publicExponent  INTEGER  -- e
      }
    }
  }
*)
begin
  var a: TASN1_Sequence;

  a.Add(TASN1_ObjectIdentifier('1.2.840.113549.1.1.1'));
  a.AddNull;
  Result.Add(a);

  var b: TASN1_Sequence;
  b.Add(aValue.modulus);
  b.Add(aValue.publicExponent);

  var c: TASN1_BitString := TASN1_DER.Encode(b);
  Result.Add(c);
end;

constructor X509_PublicKeyInfo_ECC.Create(ax, ay: TASN1_Integer);
begin
  x := ax;
  y := ay;
end;

class function X509_PublicKeyInfo_ECC.&Label: string;
begin
  Result := 'PUBLIC KEY';
end;

class operator X509_PublicKeyInfo_ECC.Implicit(aValue: X509_PublicKeyInfo_ECC): TASN1_Sequence;
(* rfc5480
  SubjectPublicKeyInfo ::= SEQUENCE {
    SEQUENCE {
      id-ecPublicKey OBJECT IDENTIFIER ::= {
        iso(1) member-body(2) us(840) ansi-X9-62(10045) keyType(2) 1
      },
      secp256r1 OBJECT IDENTIFIER ::= {
         iso(1) member-body(2) us(840) ansi-X9-62(10045) curves(3)
         prime(1) 7
      }
    }
    subjectPublicKey  BIT STRING {
      0x04 -- uncompressed
      Q.X
      Q.Y
    }
  }
*)
begin
  var a: TASN1_Sequence;

  a.Add(TASN1_ObjectIdentifier('1.2.840.10045.2.1'));
  a.Add(TASN1_ObjectIdentifier('1.2.840.10045.3.1.7'));
  Result.Add(a);

  var b := [$04{uncompressed}] + aValue.x.Value + aValue.y.Value;
  Result.Add(TASN1_BitString(b));
end;

end.
