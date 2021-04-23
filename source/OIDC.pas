unit OIDC;

interface

uses
  System.Classes, System.Generics.Collections, System.Net.URLClient;

type
  TTokenType = (none, basic, bearer);

  TTokenTypeHelper = record helper for TTokenType
  public
    function ToString: string;
  end;

  TAuthorization = record
  strict private
    FTokenType: TTokenType;
    FValue: string;
    function GetCredential: string;
  public
    constructor CreateBasic(UserName, Password: string);
    constructor CreateBearer(aToken: string);
    class operator Implicit(Value: TAuthorization): TNetHeader;
    class operator Implicit(Value: TAuthorization): TNetHeaders;
  end;

  Ttoken_endpoint_auth_method = (client_secret_post, client_secret_basic);

  Ttoken_endpoint_auth_method_Helper = record helper for Ttoken_endpoint_auth_method
  public
    function SetValue(Value: string): Boolean;
    function ToString: string;
  end;

  Ttoken_endpoint_auth_methods_supported = record
  strict private
    FValue: set of Ttoken_endpoint_auth_method;
  public
    class function Name: string; static;
    class operator Initialize(out Dest: Ttoken_endpoint_auth_methods_supported);
    class operator Implicit(Value: TArray<string>): Ttoken_endpoint_auth_methods_supported;
    class operator Implicit(Value: Ttoken_endpoint_auth_methods_supported):
        TArray<string>;
    class operator In(a: Ttoken_endpoint_auth_method; b: Ttoken_endpoint_auth_methods_supported):
        Boolean;
  end;

  Tgrant_type = (authorization_code, refresh_token);

  Tgrant_type_Helper = record helper for Tgrant_type
  public
    function SetValue(Value: string): Boolean;
    function ToString: string;
  end;

  Tgrant_types_supported = record
  strict private
    FValue: set of Tgrant_type;
  public
    class function Name: string; static;
    class operator Implicit(Value: TArray<string>): Tgrant_types_supported;
    class operator In(a: Tgrant_type; b: Tgrant_types_supported): Boolean;
    class operator Initialize(out Dest: Tgrant_types_supported);
  end;

  Tcode_challenge_method = (plain, S256, ES256, RS256);

  Tcode_challenge_method_Helper = record helper for Tcode_challenge_method
  public
    function code_challenge(code_verifier: string): string;
    function SetValue(Value: string): Boolean;
    function ToString: string;
  end;

  Tcode_challenge_methods_supported = record
  strict private
    FValue: set of Tcode_challenge_method;
  public
    class function Name: string; static;
    class operator Implicit(Value: TArray<string>):
        Tcode_challenge_methods_supported;
    class operator Implicit(Value: Tcode_challenge_methods_supported): TArray<string>;
    class operator Implicit(Value: Tcode_challenge_methods_supported): Boolean;
    class operator In(a: Tcode_challenge_method; b: Tcode_challenge_methods_supported):
        Boolean;
    class operator Initialize(out Dest: Tcode_challenge_methods_supported);
  end;

  Tresponse_mode = (form_post, fragment, query);

  Tresponse_mode_Helper = record helper for Tresponse_mode
  public
    function SetValue(Value: string): Boolean;
    function ToString: string;
  end;

  Tresponse_modes_supported = record
  strict private
    FValue: set of Tresponse_mode;
  public
    class function Name: string; static;
    class operator Implicit(Value: TArray<string>): Tresponse_modes_supported;
    class operator Implicit(Value: Tresponse_modes_supported): TArray<string>;
    class operator Implicit(Value: Tresponse_modes_supported): Boolean;
    class operator In(a: Tresponse_mode; b: Tresponse_modes_supported):
        Boolean;
    class operator Initialize(out Dest: Tresponse_modes_supported);
  end;

  TKeyPair = TPair<string, string>;
  TKeyPairs = TArray<TKeyPair>;

  TOIDC_Discovery = record // rfc8414
  strict private
    FKeys: TKeyPairs;
  public
    authorization_endpoint: string;
    code_challenge_methods_supported: Tcode_challenge_methods_supported;
    device_authorization_endpoint: string;
    grant_types_supported: Tgrant_types_supported;
    issuer: string;
    jwks_uri: string;
    response_modes_supported: Tresponse_modes_supported;
    response_types_supported: TArray<string>;
    revocation_endpoint: string;
    scopes_supported: TArray<string>;
    token_endpoint: string;
    token_endpoint_auth_methods_supported: Ttoken_endpoint_auth_methods_supported;
    userinfo_endpoint: string;
    constructor Create(aConfig: string);
    function GetPublicKey(kid: string): string;
    class operator Implicit(Value: string): TOIDC_Discovery;
    class operator Initialize(out Dest: TOIDC_Discovery);
  end;

  TIODC_Authorization_Request = record // rfc6749
  strict private
    authorization_endpoint: string;
    Fscope: TArray<string>;
    function ConstructURI: string;
    function Get_scope: string;
  public
    client_id: string;
    nonce: string;
    prompt: string;
    redirect_uri: string;
    response_type: string;
    state: string;
    code_challenge_method: Tcode_challenge_method;
    code_challenge: string;
    constructor Create(aauthorization_endpoint: string);
    procedure Add_scope(Value: string);
    class operator Implicit(Value: TIODC_Authorization_Request): string;
    class operator Initialize(out Dest: TIODC_Authorization_Request);
    property scope: string read Get_scope;
  end;

  TOIDC_Token_Request = record
  strict private
    client_id: string;
    client_secret: string;
    code_or_refresh_token: string;
    token_endpoint_auth_method: Ttoken_endpoint_auth_method;
    grant_type: Tgrant_type;
    Payload: TStrings;
    code_verifier: string;
    redirect_uri: string;
    function ConstructPayload: TStrings;
    function grant_type_Name: string;
    function grant_type_Value: string;
  public
    constructor Create(agrant_type: Tgrant_type; atoken_endpoint_auth_method,
        aclient_id, aclient_secret, acode_or_refresh_token: string; acode_verifier:
        string = ''; aredirect_uri: string = '');
    class operator Assign(var Dest: TOIDC_Token_Request; const [ref] Src:
        TOIDC_Token_Request);
    class operator Finalize(var Dest: TOIDC_Token_Request);
    class operator Implicit(const [ref] Value: TOIDC_Token_Request): TStrings;
    class operator Implicit(const [ref] Value: TOIDC_Token_Request): TNetHeaders;
    class operator Initialize(out Dest: TOIDC_Token_Request);
  end;

  TIODC_Revocation_Request = record
  strict private
    Payload: TStrings;
    token: string;
    function ConstructPayload: TStrings;
  public
    constructor Create(atoken: string);
    class operator Finalize(var Dest: TIODC_Revocation_Request);
    class operator Implicit(const [ref] Value: TIODC_Revocation_Request): TStrings;
    class operator Implicit(const [ref] Value: TIODC_Revocation_Request): TNetHeaders;
    class operator Initialize(out Dest: TIODC_Revocation_Request);
  end;

implementation

uses
  System.Hash, System.JSON, System.Net.HttpClient, System.NetConsts,
  System.NetEncoding, System.RTLConsts, System.SysUtils, REST.Types,
  ASN1, ASN1.X509, JWKS, System.NetEncoding.Base64Url;

type
  TJSONArrayHelper = class helper for TJSONArray
    function AsStrings: TArray<string>;
  end;

function TJSONArrayHelper.AsStrings: TArray<string>;
begin
  SetLength(Result, Count);
  for var i := 0 to Count - 1 do
    Result[i] := Items[i].Value;
end;

function TTokenTypeHelper.ToString: string;
begin
  case Self of
    none: Result := '';
    basic: Result := 'Basic';
    bearer: Result := 'Bearer';
    else
      raise Exception.CreateResFmt(@SInvalidPropertyType, [Integer(Self).ToString]);
  end;
end;

constructor TAuthorization.CreateBasic(UserName, Password: string);
begin
  FTokenType := basic;
  var B := TBase64Encoding.Create(0);
  try
    FValue := B.Encode(UserName + ':' + Password);
  finally
    B.Free;
  end;
end;

constructor TAuthorization.CreateBearer(aToken: string);
begin
  FTokenType := bearer;
  FValue := aToken;
end;

function TAuthorization.GetCredential: string;
begin
  Result := FTokenType.ToString + ' ' + FValue;
end;

class operator TAuthorization.Implicit(Value: TAuthorization): TNetHeaders;
begin
  Result := [Value];
end;

class operator TAuthorization.Implicit(Value: TAuthorization): TNetHeader;
begin
  Result := TNetHeader.Create(sAuthorization, Value.GetCredential);
end;

function Ttoken_endpoint_auth_method_Helper.SetValue(Value: string): Boolean;
begin
       if Value = 'client_secret_post'  then Self := client_secret_post
  else if Value = 'client_secret_basic' then Self := client_secret_basic
  else Exit(False);
  Result := True;
end;

function Ttoken_endpoint_auth_method_Helper.ToString: string;
begin
  case Self of
    client_secret_post:  Result := 'client_secret_post';
    client_secret_basic: Result := 'client_secret_basic';
    else
      raise Exception.CreateResFmt(@SInvalidPropertyType, [Integer(Self).ToString]);
  end;
end;

class function Ttoken_endpoint_auth_methods_supported.Name: string;
begin
  Result := 'token_endpoint_auth_methods_supported';
end;

class operator Ttoken_endpoint_auth_methods_supported.Implicit(
  Value: TArray<string>): Ttoken_endpoint_auth_methods_supported;
begin
  var b: Ttoken_endpoint_auth_method;
  for var a in Value do
    if b.SetValue(a) then
      Result.FValue := Result.FValue + [b];
end;

class operator Ttoken_endpoint_auth_methods_supported.Implicit(Value:
    Ttoken_endpoint_auth_methods_supported): TArray<string>;
begin
  Result := [];
  for var a in Value.FValue do
    Result := Result + [a.ToString];
end;

class operator Ttoken_endpoint_auth_methods_supported.In(a: Ttoken_endpoint_auth_method; b:
    Ttoken_endpoint_auth_methods_supported): Boolean;
begin
  Result := a in b.FValue;
end;

class operator Ttoken_endpoint_auth_methods_supported.Initialize(out Dest:
    Ttoken_endpoint_auth_methods_supported);
begin
  Dest.FValue := [];
end;

constructor TOIDC_Discovery.Create(aConfig: string);
begin
  var J := TJSONObject.ParseJSONValue(aConfig) as TJSONObject;
  try
    J.TryGetValue<string>('issuer',                        issuer);
    J.TryGetValue<string>('authorization_endpoint',        authorization_endpoint);
    J.TryGetValue<string>('device_authorization_endpoint', device_authorization_endpoint);
    J.TryGetValue<string>('token_endpoint',                token_endpoint);
    J.TryGetValue<string>('userinfo_endpoint',             userinfo_endpoint);
    J.TryGetValue<string>('revocation_endpoint',           revocation_endpoint);
    J.TryGetValue<string>('jwks_uri',                      jwks_uri);

    var A: TJSONArray;
    if J.TryGetValue<TJSONArray>('scopes_supported', A) then
      scopes_supported := A.AsStrings;

    if J.TryGetValue<TJSONArray>(response_modes_supported.Name, A) then
      response_modes_supported := A.AsStrings;

    if J.TryGetValue<TJSONArray>('response_types_supported', A) then
      response_types_supported := A.AsStrings;

    if J.TryGetValue<TJSONArray>(token_endpoint_auth_methods_supported.Name, A) then
      token_endpoint_auth_methods_supported := A.AsStrings;

    if J.TryGetValue<TJSONArray>(grant_types_supported.Name, A) then
      grant_types_supported := A.AsStrings;

    if J.TryGetValue<TJSONArray>(code_challenge_methods_supported.Name, A) then
      code_challenge_methods_supported := A.AsStrings;
  finally
    J.Free;
  end;
end;

function TOIDC_Discovery.GetPublicKey(kid: string): string;
begin
  if FKeys = nil then begin
    var H := THTTPClient.Create;
    try
      var a: TJWKS := H.Get(jwks_uri).ContentAsString(TEncoding.UTF8);
      for var i := 0 to a.Count - 1 do begin
        var c: TPEM;
        if a.Keys[i].alg = Talg.Talg_type.ES256 then begin
          var b := X509_PublicKeyInfo_ECC.Create(a.Keys[i].x, a.Keys[i].y);
          c.SetValue(b.&Label, TASN1_DER.Encode(b));
        end else if a.Keys[i].alg = Talg.Talg_type.RS256 then begin
          var b := X509_PublicKeyInfo_RSA.Create(a.Keys[i].n, a.Keys[i].e);
          c.SetValue(b.&Label, TASN1_DER.Encode(b));
        end;
        FKeys := FKeys + [TKeyPair.Create(a.Keys[i].kid, c)];
      end;
    finally
      H.Free;
    end;
  end;

  for var K in FKeys do
    if K.Key = kid then
      Exit(K.Value);
end;

class operator TOIDC_Discovery.Implicit(Value: string): TOIDC_Discovery;
begin
  Result := TOIDC_Discovery.Create(Value);
end;

class operator TOIDC_Discovery.Initialize(out Dest: TOIDC_Discovery);
begin
  with Dest do begin
    FKeys := [];
    authorization_endpoint := '';
    code_challenge_methods_supported := [];
    device_authorization_endpoint := '';
    grant_types_supported := [];
    issuer := '';
    jwks_uri := '';
    response_modes_supported := [];
    response_types_supported := [];
    revocation_endpoint := '';
    scopes_supported := [];
    token_endpoint := '';
    token_endpoint_auth_methods_supported := [];
    userinfo_endpoint := '';
  end;
end;

function Tgrant_type_Helper.SetValue(Value: string): Boolean;
begin
       if Value = 'authorization_code' then Self := authorization_code
  else if Value = 'refresh_token'  then Self := refresh_token
  else Exit(False);
  Result := True;
end;

function Tgrant_type_Helper.ToString: string;
begin
  case Self of
    authorization_code: Result := 'authorization_code';
    refresh_token:      Result := 'refresh_token';
    else
      raise Exception.CreateResFmt(@SInvalidPropertyType, [Integer(Self).ToString]);
  end;
end;

class function Tgrant_types_supported.Name: string;
begin
  Result := 'grant_types_supported';
end;

class operator Tgrant_types_supported.Implicit(
  Value: TArray<string>): Tgrant_types_supported;
begin
  var b: Tgrant_type;
  for var a in Value do
    if b.SetValue(a) then
      Result.FValue := Result.FValue + [b];
end;

class operator Tgrant_types_supported.In(a: Tgrant_type; b:
    Tgrant_types_supported): Boolean;
begin
  Result := a in b.FValue;
end;

class operator Tgrant_types_supported.Initialize(out Dest:
    Tgrant_types_supported);
begin
  Dest.FValue := [];
end;

function Tcode_challenge_method_Helper.code_challenge(code_verifier: string):
    string;
begin
  case Self of
    plain: Result := code_verifier;
    S256: Result := TNetEncoding.Base64Url.EncodeBytesToString(THashSHA2.GetHashBytes(code_verifier));
    else
      raise Exception.CreateResFmt(@StrEActionNoSuported, [ToString]);
  end;
end;

function Tcode_challenge_method_Helper.SetValue(Value: string): Boolean;
begin
       if Value = 'plain' then Self := plain
  else if Value = 'S256'  then Self := S256
  else if Value = 'ES256' then Self := ES256
  else if Value = 'RS256' then Self := RS256
  else Exit(False);
  Result := True;
end;

function Tcode_challenge_method_Helper.ToString: string;
begin
  case Self of
    plain: Result := 'plain';
    S256:  Result := 'S256';
    ES256: Result := 'ES256';
    RS256: Result := 'RS256';
    else
      raise Exception.CreateResFmt(@SInvalidPropertyType, [Integer(Self).ToString]);
  end;
end;

constructor TIODC_Authorization_Request.Create(aauthorization_endpoint: string);
begin
  authorization_endpoint := aauthorization_endpoint;
end;

procedure TIODC_Authorization_Request.Add_scope(Value: string);
begin
  for var s in Fscope do
    if s = Value then Exit;
  Fscope := Fscope + [Value];
end;

function TIODC_Authorization_Request.ConstructURI: string;
begin
  var U := TURI.Create(authorization_endpoint);

  U.AddParameter('client_id', client_id);
  U.AddParameter('scope', scope);
  U.AddParameter('response_type', response_type);
  if prompt <> '' then U.AddParameter('prompt', prompt);
  if nonce <> '' then U.AddParameter('nonce', nonce);
  if redirect_uri <> '' then U.AddParameter('redirect_uri', redirect_uri);
  if code_challenge <> '' then begin
    U.AddParameter('code_challenge_method', code_challenge_method.ToString);
    U.AddParameter('code_challenge', code_challenge);
  end;

  Result := U.ToString;
end;

function TIODC_Authorization_Request.Get_scope: string;
begin
  Result := string.Join(' ', Fscope);
end;

class operator TIODC_Authorization_Request.Implicit(
  Value: TIODC_Authorization_Request): string;
begin
  Result := Value.ConstructURI;
end;

class operator TIODC_Authorization_Request.Initialize(
  out Dest: TIODC_Authorization_Request);
begin
  Dest.authorization_endpoint := '';
  Dest.response_type := '';
  Dest.client_id := '';
  Dest.redirect_uri := '';
  Dest.Fscope := [];
  Dest.state := '';
  Dest.prompt := '';
  Dest.nonce := '';
  Dest.code_challenge := '';
end;

constructor TOIDC_Token_Request.Create(agrant_type: Tgrant_type;
    atoken_endpoint_auth_method, aclient_id, aclient_secret,
    acode_or_refresh_token: string; acode_verifier: string = ''; aredirect_uri:
    string = '');
begin
  grant_type := agrant_type;
  token_endpoint_auth_method.SetValue(atoken_endpoint_auth_method);
  client_id := aclient_id;
  client_secret := aclient_secret;
  code_or_refresh_token := acode_or_refresh_token;
  code_verifier := acode_verifier;
  redirect_uri := aredirect_uri;
end;

function TOIDC_Token_Request.ConstructPayload: TStrings;
begin
  Payload.Clear;
  if token_endpoint_auth_method = client_secret_post then begin
    Payload.AddPair('client_id',     client_id);
    if client_secret <> '' then
      Payload.AddPair('client_secret',       client_secret);
  end;
  Payload.AddPair('grant_type',      grant_type_value);
  if code_verifier <> '' then
    Payload.AddPair('code_verifier', code_verifier);
  if redirect_uri <> '' then
    Payload.AddPair('redirect_uri',  redirect_uri);
  Payload.AddPair(grant_type_Name,   code_or_refresh_token);
  Result := Payload;
end;

function TOIDC_Token_Request.grant_type_Name: string;
begin
  case grant_type of
    authorization_code: Result := 'code';
    refresh_token:      Result := 'refresh_token';
    else
      raise Exception.CreateResFmt(@SInvalidPropertyType, [Integer(grant_type).ToString]);
  end;
end;

function TOIDC_Token_Request.grant_type_value: string;
begin
  case grant_type of
    authorization_code: Result := 'authorization_code';
    refresh_token:      Result := 'refresh_token';
    else
      raise Exception.CreateResFmt(@SInvalidPropertyType, [Integer(grant_type).ToString]);
  end;
end;

class operator TOIDC_Token_Request.Assign(var Dest: TOIDC_Token_Request;
    const [ref] Src: TOIDC_Token_Request);
begin
  raise Exception.CreateResFmt(@StrEActionNoSuported, ['TOIDC_Token_Request']);
end;

class operator TOIDC_Token_Request.Finalize(
  var Dest: TOIDC_Token_Request);
begin
  Dest.Payload.Free;
  Dest.Payload := nil;
end;

class operator TOIDC_Token_Request.Implicit(const [ref] Value:
    TOIDC_Token_Request): TStrings;
begin
  Result := Value.ConstructPayload;
end;

class operator TOIDC_Token_Request.Implicit(const [ref] Value:
    TOIDC_Token_Request): TNetHeaders;
begin
  Result := [TNetHeader.Create(sContentType, CONTENTTYPE_APPLICATION_X_WWW_FORM_URLENCODED)];
  if Value.token_endpoint_auth_method = client_secret_basic then
    Result := Result + [TAuthorization.CreateBasic(Value.client_id, Value.client_secret)];
end;

class operator TOIDC_Token_Request.Initialize(
  out Dest: TOIDC_Token_Request);
begin
  Dest.token_endpoint_auth_method := client_secret_post;
  Dest.client_id := '';
  Dest.client_secret := '';
  Dest.code_verifier := '';
  Dest.redirect_uri := '';
  Dest.code_or_refresh_token := '';
  Dest.Payload := TStringList.Create;
end;

constructor TIODC_Revocation_Request.Create(atoken: string);
begin
  token := atoken;
end;

function TIODC_Revocation_Request.ConstructPayload: TStrings;
begin
  Payload.Clear;
  Payload.AddPair('token', token);
  Result := Payload;
end;

class operator TIODC_Revocation_Request.Finalize(var Dest:
    TIODC_Revocation_Request);
begin
  Dest.Payload.Free;
  Dest.Payload := nil;
end;

class operator TIODC_Revocation_Request.Implicit(
  const [ref] Value: TIODC_Revocation_Request): TStrings;
begin
  Result := Value.ConstructPayload;
end;

class operator TIODC_Revocation_Request.Implicit(
  const [ref] Value: TIODC_Revocation_Request): TNetHeaders;
begin
  Result := [TNetHeader.Create(sContentType, CONTENTTYPE_APPLICATION_X_WWW_FORM_URLENCODED)];
end;

class operator TIODC_Revocation_Request.Initialize(out Dest:
    TIODC_Revocation_Request);
begin
  Dest.token := '';
  Dest.Payload := TStringList.Create;
end;

class function Tcode_challenge_methods_supported.Name: string;
begin
  Result := 'code_challenge_methods_supported';
end;

class operator Tcode_challenge_methods_supported.Implicit(Value:
    TArray<string>): Tcode_challenge_methods_supported;
begin
  var b: Tcode_challenge_method;
  for var a in Value do
    if b.SetValue(a) then
      Result.FValue := Result.FValue + [b];
end;

class operator Tcode_challenge_methods_supported.Implicit(
  Value: Tcode_challenge_methods_supported): TArray<string>;
begin
  Result := [];
  for var a in Value.FValue do
    Result := Result + [a.ToString];
end;

class operator Tcode_challenge_methods_supported.Implicit(
  Value: Tcode_challenge_methods_supported): Boolean;
begin
  Result := Value.FValue <> [];
end;

class operator Tcode_challenge_methods_supported.In(a: Tcode_challenge_method; b:
    Tcode_challenge_methods_supported): Boolean;
begin
  Result := a in b.FValue;
end;

class operator Tcode_challenge_methods_supported.Initialize(out Dest:
    Tcode_challenge_methods_supported);
begin
  Dest.FValue := [];
end;

function Tresponse_mode_Helper.SetValue(Value: string): Boolean;
begin
       if Value = 'form_post' then Self := form_post
  else if Value = 'fragment'  then Self := fragment
  else if Value = 'query'     then Self := query
  else Exit(False);
  Result := True;
end;

function Tresponse_mode_Helper.ToString: string;
begin
  case Self of
    form_post: Result := 'form_post';
    fragment:  Result := 'fragment';
    query:     Result := 'query';
    else
      raise Exception.CreateResFmt(@SInvalidPropertyType, [Integer(Self).ToString]);
  end;
end;

class function Tresponse_modes_supported.Name: string;
begin
  Result := 'response_modes_supported';
end;

class operator Tresponse_modes_supported.Implicit(Value: TArray<string>):
    Tresponse_modes_supported;
begin
  var b: Tresponse_mode;
  for var a in Value do
    if b.SetValue(a) then
      Result.FValue := Result.FValue + [b];
end;

class operator Tresponse_modes_supported.Implicit(Value:
    Tresponse_modes_supported): TArray<string>;
begin
  Result := [];
  for var a in Value.FValue do
    Result := Result + [a.ToString];
end;

class operator Tresponse_modes_supported.Implicit(Value:
    Tresponse_modes_supported): Boolean;
begin
  Result := Value.FValue <> [];
end;

class operator Tresponse_modes_supported.In(a: Tresponse_mode; b:
    Tresponse_modes_supported): Boolean;
begin
  Result := a in b.FValue;
end;

class operator Tresponse_modes_supported.Initialize(out Dest:
    Tresponse_modes_supported);
begin
  Dest.FValue := [];
end;

end.
