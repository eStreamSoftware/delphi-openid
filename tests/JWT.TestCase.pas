unit JWT.TestCase;

interface

uses
  TestFramework,
  JWT,
  JWKS;

type
  TTestCase_Base64Url = class(TTestCase)
  public
    class constructor Create;
  published
    procedure DecodeBytes;
    procedure DecodeString;
    procedure EncodeBytes;
    procedure EncodeString;
  end;

  TTestCase_JWT = class(TTestCase)
  const HS_KEY = 'secretsecretsecretsecretsecretsecretsecretsecretsecretsecretsecret';
  private
    function Get_Sample: TJWT;
  public
    class constructor Create;
  published
    procedure HS256;
    procedure HS384;
    procedure HS512;
    procedure InvalidToken1;
    procedure InvalidToken2;
    procedure None;
    procedure UnsignToken;
  end;

implementation

uses
  System.Classes, System.NetEncoding, System.SysUtils,
  JWT.HS,
  System.NetEncoding.Base64Url;

class constructor TTestCase_Base64Url.Create;
begin
  RegisterTest(Suite);
end;

procedure TTestCase_Base64Url.DecodeBytes;
begin
  CheckEquals('~~~Hello~~~ ??? ~~~World~~~ .', TEncoding.ANSI.GetString(TNetEncoding.Base64Url.Decode(TEncoding.ANSI.GetBytes('fn5-SGVsbG9-fn4gPz8_IH5-fldvcmxkfn5-IC4'))));
  CheckEquals('~~~Hello~~~ ??? ~~~World~~~ ..', TEncoding.ANSI.GetString(TNetEncoding.Base64Url.Decode(TEncoding.ANSI.GetBytes('fn5-SGVsbG9-fn4gPz8_IH5-fldvcmxkfn5-IC4u'))));
  CheckEquals('~~~Hello~~~ ??? ~~~World~~~ ...', TEncoding.ANSI.GetString(TNetEncoding.Base64Url.Decode(TEncoding.ANSI.GetBytes('fn5-SGVsbG9-fn4gPz8_IH5-fldvcmxkfn5-IC4uLg'))));
end;

procedure TTestCase_Base64Url.DecodeString;
begin
  CheckEquals('~~~Hello~~~ ??? ~~~World~~~ .', TNetEncoding.Base64Url.Decode('fn5-SGVsbG9-fn4gPz8_IH5-fldvcmxkfn5-IC4'));
  CheckEquals('~~~Hello~~~ ??? ~~~World~~~ ..', TNetEncoding.Base64Url.Decode('fn5-SGVsbG9-fn4gPz8_IH5-fldvcmxkfn5-IC4u'));
  CheckEquals('~~~Hello~~~ ??? ~~~World~~~ ...', TNetEncoding.Base64Url.Decode('fn5-SGVsbG9-fn4gPz8_IH5-fldvcmxkfn5-IC4uLg'));
end;

procedure TTestCase_Base64Url.EncodeBytes;
begin
  CheckEquals('fn5-SGVsbG9-fn4gPz8_IH5-fldvcmxkfn5-IC4', TEncoding.ANSI.GetString(TNetEncoding.Base64Url.Encode(TEncoding.ANSI.GetBytes('~~~Hello~~~ ??? ~~~World~~~ .'))));
  CheckEquals('fn5-SGVsbG9-fn4gPz8_IH5-fldvcmxkfn5-IC4u', TEncoding.ANSI.GetString(TNetEncoding.Base64Url.Encode(TEncoding.ANSI.GetBytes('~~~Hello~~~ ??? ~~~World~~~ ..'))));
  CheckEquals('fn5-SGVsbG9-fn4gPz8_IH5-fldvcmxkfn5-IC4uLg', TEncoding.ANSI.GetString(TNetEncoding.Base64Url.Encode(TEncoding.ANSI.GetBytes('~~~Hello~~~ ??? ~~~World~~~ ...'))));
end;

procedure TTestCase_Base64Url.EncodeString;
begin
  CheckEquals('fn5-SGVsbG9-fn4gPz8_IH5-fldvcmxkfn5-IC4', TNetEncoding.Base64Url.Encode('~~~Hello~~~ ??? ~~~World~~~ .'));
  CheckEquals('fn5-SGVsbG9-fn4gPz8_IH5-fldvcmxkfn5-IC4u', TNetEncoding.Base64Url.Encode('~~~Hello~~~ ??? ~~~World~~~ ..'));
  CheckEquals('fn5-SGVsbG9-fn4gPz8_IH5-fldvcmxkfn5-IC4uLg', TNetEncoding.Base64Url.Encode('~~~Hello~~~ ??? ~~~World~~~ ...'));
end;

class constructor TTestCase_JWT.Create;
begin
  RegisterTest(Suite);
end;

function TTestCase_JWT.Get_Sample: TJWT;
begin
  Result.Header.kid.ValueString := '1';
  Result.Claims.iss.ValueString := 'joe';
  Result.Claims.exp.ValueNumeric := 1300819380;
  Result.Claims.Add('custom1', 'admin');
  Result.Claims.Add('custom2', true);
  Result.Claims.Add('custom3', 99);
end;

procedure TTestCase_JWT.HS256;
begin
  var J: TJWT := Get_Sample;
  var Token := 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6IjEifQ.'
             + 'eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImN1c3RvbTEiOiJhZG1pbiIsImN1c3RvbTIiOnRydWUsImN1c3RvbTMiOjk5fQ.'
             + 'J0tpAhyZErDJMywfUPnFx72c310rFZkhXUQB7_oohRQ';
  CheckEquals(Token, J.Sign(Talg.Talg_type.HS256, HS_KEY));
  status(J);
  CheckEquals(Token, J);

  J := Token;
  CheckFalse(J);
  CheckTrue(J.Validate(HS_KEY));
  CheckTrue(J);
end;

procedure TTestCase_JWT.HS384;
begin
  var J: TJWT := Get_Sample;
  var Token := 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzM4NCIsImtpZCI6IjEifQ.'
             + 'eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImN1c3RvbTEiOiJhZG1pbiIsImN1c3RvbTIiOnRydWUsImN1c3RvbTMiOjk5fQ.'
             + 'MxE9kPeuWOqMXR7tcUmkp7w1SHvW1zf6GxqMYDKbLFhSGwud_pyedZe013-PN4ux';
  CheckEquals(Token, J.Sign(Talg.Talg_type.HS384, HS_KEY));
  status(J);
  CheckEquals(Token, J);

  J := Token;
  CheckFalse(J);
  CheckTrue(J.Validate(HS_KEY));
  CheckTrue(J);
end;

procedure TTestCase_JWT.HS512;
begin
  var J: TJWT := Get_Sample;
  var Token := 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiIsImtpZCI6IjEifQ.'
             + 'eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImN1c3RvbTEiOiJhZG1pbiIsImN1c3RvbTIiOnRydWUsImN1c3RvbTMiOjk5fQ.'
             + 'wjnEsMA_ORKfXJ7mlM-lybLiCmH0VVtphjdNT8OcG1lE-kC-yHqC3xCPFQfZ7oG9rSxJNkAZ4yduif6LwfXpwA';
  CheckEquals(Token, J.Sign(Talg.Talg_type.HS512, HS_KEY));
  status(J);
  CheckEquals(Token, J);

  J := Token;
  CheckFalse(J);
  CheckTrue(J.Validate(HS_KEY));
  CheckTrue(J);
end;

procedure TTestCase_JWT.InvalidToken1;
begin
  var J: TJWT;
  var Token := 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImN1c3RvbSI6dHJ1ZX0.6Ha58Z9mDx4YbkuC9uyRunxRFYCUZV3mt06527x9DLU';
  StartExpectingException(Exception);
  J := Token.Remove(20);
end;

procedure TTestCase_JWT.InvalidToken2;
begin
  var J: TJWT;
  var Token := 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImN1c3RvbSI6dHJ1ZX0.6Ha58Z9mDx4YbkuC9uyRunxRFYCUZV3mt06527x9DLU';

  J := Token + '1';
  CheckFalse(J);

  CheckFalse(J.Validate(HS_KEY));

  StartExpectingException(Exception);
  CheckEquals('', J);
end;

procedure TTestCase_JWT.None;
begin
  var J: TJWT := Get_Sample;
  J.Header.kid.Clear;
  var Token := 'eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.'
             + 'eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImN1c3RvbTEiOiJhZG1pbiIsImN1c3RvbTIiOnRydWUsImN1c3RvbTMiOjk5fQ.';
  CheckEquals(Token, J.Sign(Talg.Talg_type.none, ''));
  status(J);
  CheckEquals(Token, J);

  J := Token;
  CheckFalse(J);
  CheckTrue(J.Validate(''));
  CheckTrue(J);
end;

procedure TTestCase_JWT.UnsignToken;
begin
  var J: TJWT;
  J.Claims.iss.ValueString := 'joe';
  J.Claims.exp.ValueNumeric := 1300819380;
  J.Claims.Add('custom', true);
  StartExpectingException(Exception);
  CheckEquals('', J);
end;

initialization
  TTestCase_Base64Url.ClassName;
  TTestCase_JWT.ClassName;
end.
