unit OIDC.TestCase;

interface

uses
  TestFramework;

type
  TOIDC_TestCase = class(TTestCase)
  public
    class constructor Create;
  published
    procedure Test_TAuthorization;
    procedure Test_Tcode_challenge_method;
    procedure Test_Tcode_challenge_methods_supported;
    procedure Test_Tgrant_type;
    procedure Test_Tgrant_types_supported;
    procedure Test_TTokenType;
    procedure Test_Tresponse_mode;
    procedure Test_Tresponse_modes_supported;
    procedure Test_Ttoken_endpoint_auth_method;
    procedure Test_Ttoken_endpoint_auth_methods_supported;
  end;

implementation

uses
  System.Net.URLClient, System.NetConsts,
  OIDC;

class constructor TOIDC_TestCase.Create;
begin
  RegisterTest(Suite);
end;

procedure TOIDC_TestCase.Test_TAuthorization;
begin
  var a := TAuthorization.CreateBasic('9p85csggqsdp5qko8iadnqcpm1sue69b', 'tvhQglvq7PQxugxsE7RS3mhP');
  var H: TNetHeader := a;
  CheckEquals(sAuthorization, H.Name);
  CheckEquals('Basic OXA4NWNzZ2dxc2RwNXFrbzhpYWRucWNwbTFzdWU2OWI6dHZoUWdsdnE3UFF4dWd4c0U3UlMzbWhQ', H.Value);

  a := TAuthorization.CreateBearer('ya29.a0AfH6SMBZPAiZXn4Blzn117y1wsBN9mdonNGvAssSKB_9vkFrocEEIyT_a2cHGKktrjXbh3hhFyg0lgIWFxWJ_ppkcxjf0qZFyJH9F985DfWR0LbrfC_Yx1fDRr8jg64mcDvcyJ1Vx0KnGlyPJQqls-U9ZTd4');
  H := a;
  CheckEquals(sAuthorization, H.Name);
  CheckEquals('Bearer ya29.a0AfH6SMBZPAiZXn4Blzn117y1wsBN9mdonNGvAssSKB_9vkFrocEEIyT_a2cHGKktrjXbh3hhFyg0lgIWFxWJ_ppkcxjf0qZFyJH9F985DfWR0LbrfC_Yx1fDRr8jg64mcDvcyJ1Vx0KnGlyPJQqls-U9ZTd4', H.Value);
end;

procedure TOIDC_TestCase.Test_Tcode_challenge_method;
begin
  var a: Tcode_challenge_method;
  a := plain;
  CheckEquals('plain', a.ToString);

  a := S256;
  CheckEquals('S256', a.ToString);

  a := ES256;
  CheckEquals('ES256', a.ToString);

  a := RS256;
  CheckEquals('RS256', a.ToString);

  CheckTrue(a.SetValue('plain'));
  CheckTrue(plain = a);

  CheckTrue(a.SetValue('S256'));
  CheckTrue(S256 = a);

  CheckTrue(a.SetValue('ES256'));
  CheckTrue(ES256 = a);

  CheckTrue(a.SetValue('RS256'));
  CheckTrue(RS256 = a);

  CheckFalse(a.SetValue('invalid'));
end;

procedure TOIDC_TestCase.Test_Tcode_challenge_methods_supported;
begin
  var a: Tcode_challenge_methods_supported;
  CheckEquals('code_challenge_methods_supported', a.Name);
  CheckFalse(a);

  a := ['invalid'];
  CheckFalse(a);
  CheckFalse(plain in a);
  CheckFalse(S256 in a);
  CheckFalse(ES256 in a);
  CheckFalse(RS256 in a);

  a := ['plain'];
  CheckTrue(a);
  CheckTrue(plain in a);
  CheckFalse(S256 in a);
  CheckFalse(ES256 in a);
  CheckFalse(RS256 in a);

  a := ['plain', 'S256'];
  CheckTrue(a);
  CheckTrue(plain in a);
  CheckTrue(S256 in a);
  CheckFalse(ES256 in a);
  CheckFalse(RS256 in a);

  a := ['plain', 'S256', 'ES256'];
  CheckTrue(a);
  CheckTrue(plain in a);
  CheckTrue(S256 in a);
  CheckTrue(ES256 in a);
  CheckFalse(RS256 in a);

  a := ['plain', 'S256', 'ES256', 'RS256'];
  CheckTrue(a);
  CheckTrue(plain in a);
  CheckTrue(S256 in a);
  CheckTrue(ES256 in a);
  CheckTrue(RS256 in a);
end;

procedure TOIDC_TestCase.Test_Tgrant_type;
begin
  var a: Tgrant_type;
  a := authorization_code;
  CheckEquals('authorization_code', a.ToString);

  a := refresh_token;
  CheckEquals('refresh_token', a.ToString);

  CheckTrue(a.SetValue('authorization_code'));
  CheckTrue(authorization_code = a);

  CheckTrue(a.SetValue('refresh_token'));
  CheckTrue(refresh_token = a);

  CheckFalse(a.SetValue('invalid'));
end;

procedure TOIDC_TestCase.Test_Tgrant_types_supported;
begin
  var a: Tgrant_types_supported;
  CheckEquals('grant_types_supported', a.Name);

  a := ['invalid'];

  a := ['authorization_code'];
  CheckTrue(authorization_code in a);
  CheckFalse(refresh_token  in a);

  a := ['refresh_token'];
  CheckFalse(authorization_code in a);
  CheckTrue(refresh_token in a);

  a := ['authorization_code', 'refresh_token'];
  CheckTrue(authorization_code in a);
  CheckTrue(refresh_token in a);

  a := ['refresh_token', 'authorization_code'];
  CheckTrue(authorization_code in a);
  CheckTrue(refresh_token in a);
end;

procedure TOIDC_TestCase.Test_TTokenType;
begin
  var a: TTokenType := none;
  CheckEquals('', a.ToString);

  a := basic;
  CheckEquals('Basic', a.ToString);

  a := bearer;
  CheckEquals('Bearer', a.ToString);
end;

procedure TOIDC_TestCase.Test_Tresponse_mode;
begin
  var a: Tresponse_mode;
  a := form_post;
  CheckEquals('form_post', a.ToString);

  a := fragment;
  CheckEquals('fragment', a.ToString);

  a := query;
  CheckEquals('query', a.ToString);

  CheckTrue(a.SetValue('form_post'));
  CheckTrue(form_post = a);

  CheckTrue(a.SetValue('fragment'));
  CheckTrue(fragment = a);

  CheckTrue(a.SetValue('query'));
  CheckTrue(query = a);

  CheckFalse(a.SetValue('invalid'));
end;

procedure TOIDC_TestCase.Test_Tresponse_modes_supported;
begin
  var a: Tresponse_modes_supported;
  CheckEquals('response_modes_supported', a.Name);
  CheckFalse(a);

  a := ['invalid'];
  CheckFalse(a);
  CheckFalse(form_post in a);
  CheckFalse(fragment in a);
  CheckFalse(query in a);

  a := ['form_post'];
  CheckTrue(a);
  CheckTrue(form_post in a);
  CheckFalse(fragment in a);
  CheckFalse(query in a);

  a := ['fragment'];
  CheckTrue(a);
  CheckFalse(form_post in a);
  CheckTrue(fragment in a);
  CheckFalse(query in a);

  a := ['query'];
  CheckTrue(a);
  CheckFalse(form_post in a);
  CheckFalse(fragment in a);
  CheckTrue(query in a);

  a := ['form_post', 'fragment'];
  CheckTrue(a);
  CheckTrue(form_post in a);
  CheckTrue(fragment in a);
  CheckFalse(query in a);

  a := ['form_post', 'query'];
  CheckTrue(a);
  CheckTrue(form_post in a);
  CheckFalse(fragment in a);
  CheckTrue(query in a);

  a := ['fragment', 'query'];
  CheckTrue(a);
  CheckFalse(form_post in a);
  CheckTrue(fragment in a);
  CheckTrue(query in a);

  a := ['form_post', 'fragment', 'query'];
  CheckTrue(a);
  CheckTrue(form_post in a);
  CheckTrue(fragment in a);
  CheckTrue(query in a);
end;

procedure TOIDC_TestCase.Test_Ttoken_endpoint_auth_method;
begin
  var a: Ttoken_endpoint_auth_method;
  a := client_secret_post;
  CheckEquals('client_secret_post', a.ToString);

  a := client_secret_basic;
  CheckEquals('client_secret_basic', a.ToString);

  CheckTrue(a.SetValue('client_secret_post'));
  CheckTrue(client_secret_post = a);

  CheckTrue(a.SetValue('client_secret_basic'));
  CheckTrue(client_secret_basic = a);

  CheckFalse(a.SetValue('invalid'));
end;

procedure TOIDC_TestCase.Test_Ttoken_endpoint_auth_methods_supported;
begin
  var a: Ttoken_endpoint_auth_methods_supported;
  CheckEquals('token_endpoint_auth_methods_supported', a.Name);
  CheckFalse(client_secret_basic in a);
  CheckFalse(client_secret_post in a);

  a := ['invalid'];
  CheckFalse(client_secret_basic in a);
  CheckFalse(client_secret_post in a);

  a := ['client_secret_basic'];
  CheckTrue(client_secret_basic in a);
  CheckFalse(client_secret_post in a);

  a := ['client_secret_post'];
  CheckFalse(client_secret_basic in a);
  CheckTrue(client_secret_post in a);

  a := ['client_secret_basic', 'client_secret_post'];
  CheckTrue(client_secret_basic in a);
  CheckTrue(client_secret_post in a);

  a := ['client_secret_post', 'client_secret_basic'];
  CheckTrue(client_secret_basic in a);
  CheckTrue(client_secret_post in a);
end;

initialization
  TOIDC_TestCase.ClassName;
end.
