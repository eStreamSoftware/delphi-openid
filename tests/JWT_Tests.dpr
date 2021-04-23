program JWT_Tests;

{$define ipworks}

uses
  DUnitTestRunner,
  System.NetEncoding.Base64Url in '..\source\System.NetEncoding.Base64Url.pas',
  ASN1 in '..\source\ASN1.pas',
  ASN1.X509 in '..\source\ASN1.X509.pas',
  JWKS in '..\source\JWKS.pas',
  JWT in '..\source\JWT.pas',
  JWT.HS in '..\source\JWT.HS.pas',
  OIDC in '..\source\OIDC.pas',
  ASN1.TestCase in 'ASN1.TestCase.pas',
  JWKS.TestCase in 'JWKS.TestCase.pas',
  JWT.TestCase in 'JWT.TestCase.pas',
  OIDC.TestCase in 'OIDC.TestCase.pas';

{$R *.res}

begin
  ReportMemoryLeaksOnShutdown := True;
  RunRegisteredTests;
end.
