program JWT_ipworks_Tests;

{$define ipworks}

uses
  DUnitTestRunner,
  System.NetEncoding.Base64Url in '..\source\System.NetEncoding.Base64Url.pas',
  JWKS in '..\source\JWKS.pas',
  JWT in '..\source\JWT.pas',
  JWT.RS in '..\source\JWT.RS.pas',
  JWT.ES in '..\source\JWT.ES.pas',
  JWT.IPWorksEncrypt.TestCase in 'JWT.IPWorksEncrypt.TestCase.pas';

{$R *.res}

begin
  ReportMemoryLeaksOnShutdown := True;
  RunRegisteredTests;
end.
