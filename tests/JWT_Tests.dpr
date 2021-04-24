program JWT_Tests;

{$define ipworks}

uses
  DUnitTestRunner,
  System.NetEncoding.Base64Url in '..\source\System.NetEncoding.Base64Url.pas',
  ASN1 in '..\source\ASN1.pas',
  ASN1.X509 in '..\source\ASN1.X509.pas',
  JWKS in '..\source\JWKS.pas',
  ASN1.TestCase in 'ASN1.TestCase.pas',
  JWKS.TestCase in 'JWKS.TestCase.pas';

{$R *.res}

begin
  ReportMemoryLeaksOnShutdown := True;
  RunRegisteredTests;
end.
