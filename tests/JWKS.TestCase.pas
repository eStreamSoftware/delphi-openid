unit JWKS.TestCase;

interface

uses
  TestFramework;

type
  TJKWS_TestCase = class(TTestCase)
  public
    class constructor Create;
  published
    procedure alg;
    procedure kty;
    procedure use;
    procedure crv;
    procedure jwks;
    procedure jwk_to_pem;
    procedure jwk_without_alg;
  end;

implementation

uses
  System.Classes, System.Net.HttpClient, System.SysUtils, System.Types, System.JSON,
  JWKS, ASN1, ASN1.X509;

class constructor TJKWS_TestCase.Create;
begin
  RegisterTest(Suite);
end;

procedure TJKWS_TestCase.crv;
begin
  var o: Tcrv;
  for var i := Low(Tcrv.Tcrv_type) to High(Tcrv.Tcrv_type) do begin
    o := i;
    CheckEquals(Tcrv[i], o);
    o := Tcrv[i];
    CheckTrue(Tcrv.Tcrv_type(o) = i);
  end;
end;

procedure TJKWS_TestCase.jwks;
begin
  var P := TArray<string>.Create(
    'https://appleid.apple.com/.well-known/openid-configuration'
  , 'https://accounts.google.com/.well-known/openid-configuration'
  , 'https://oauth-login.cloud.huawei.com/.well-known/openid-configuration'
  , 'https://www.paypalobjects.com/.well-known/openid-configuration'
  , 'https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration'
  , 'https://id.singpass.gov.sg/.well-known/openid-configuration'
  , 'https://stg-id.singpass.gov.sg/.well-known/openid-configuration'
  , 'https://api.login.yahoo.com/.well-known/openid-configuration'
  );

  var H := THTTPClient.Create;
  try
    var a: TArray<IAsyncResult> := [];
    for var s in P do
      a := a + [H.BeginGet(s)];
    for var b in a do begin
      var c := H.EndAsyncHTTP(b).ContentAsString(TEncoding.UTF8);
      var j := TJSONObject.ParseJSONValue(c) as TJSONObject;
      try
        c := j.GetValue<string>('jwks_uri');
        var Keys: TJWKS := H.Get(c).ContentAsString(TEncoding.UTF8);
        status(keys.Count.ToString);
        CheckTrue(Keys.Count > 0);
      finally
        j.Free;
      end;
    end;
  finally
    H.Free;
  end;
end;

procedure TJKWS_TestCase.jwk_to_pem;
begin
  var K: TJWK :=
    '{"n":"q_GoX7XASWstA7CZs3acUgCVB2QhwhupF1WZsIr6FoI-DpLaiTlGLzEJlkLKW2nthUP35lqhXilaInOAN86sOEssz4h_uEycVpM_xLBRR'
  + '-7Rqs5iXype340JV4pNzruXX5Z_Q4D7YLvm2E1QWivvTK4FiSCeBbo78Lpkr5atiHmWEcLENoquhEHdpij3wppdDlL5eUAy4xH6Ait5IDe66Reh'
  + 'BEGfs3MLnCKyGAPIammSUruV0BEmUPfecLoXNhpuAfoGs3TO-5CIt1jmaRL2B-A2UxhPQkpE4Q-U6OJ81i4nzs34dtaQhFfT9pZqkgOwIJ4Djj7'
  + 'HI1xKOmoExMCDLw","use":"sig","kid":"774573218c6f6a2fe50e29acbc686432863fc9c3","alg":"RS256","kty":"RSA","e":"AQ'
  + 'AB"}';

  var P :=
    '-----BEGIN PUBLIC KEY-----' + sLineBreak
  + 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAq/GoX7XASWstA7CZs3acUgCVB2Qhwhup' + sLineBreak
  + 'F1WZsIr6FoI+DpLaiTlGLzEJlkLKW2nthUP35lqhXilaInOAN86sOEssz4h/uEycVpM/xLBRR+7R' + sLineBreak
  + 'qs5iXype340JV4pNzruXX5Z/Q4D7YLvm2E1QWivvTK4FiSCeBbo78Lpkr5atiHmWEcLENoquhEHd' + sLineBreak
  + 'pij3wppdDlL5eUAy4xH6Ait5IDe66RehBEGfs3MLnCKyGAPIammSUruV0BEmUPfecLoXNhpuAfoG' + sLineBreak
  + 's3TO+5CIt1jmaRL2B+A2UxhPQkpE4Q+U6OJ81i4nzs34dtaQhFfT9pZqkgOwIJ4Djj7HI1xKOmoE' + sLineBreak
  + 'xMCDLwIDAQAB' + sLineBreak
  + '-----END PUBLIC KEY-----' + sLineBreak;

  var a := X509_PublicKeyInfo_RSA.Create(K.n, K.e);
  var b: TPEM;
  b.SetValue(a.&Label, TASN1_DER.Encode(a));
  CheckEquals(P, b);
end;

procedure TJKWS_TestCase.jwk_without_alg;
begin
  var K: TJWK :=
    '{"kty":"RSA","use":"sig","kid":"bW8ZcMjBCnJZS-ibX5UQDNStvx4","x5t":"bW8ZcMjBCnJZS-ibX5UQDNStvx4"'
  + ',"n":"2a70SwgqIh8U-Shj_VJJGBheEVk2F4ygmMCRtKUAb1jMP6R1j5Mc5xaqhgzlWjckJI1lx4rha1oNLrdg8tJBxdm8V8'
  + 'xZohCOanJ52uAwoc6FFTY3VRLaUZSJ3zCXfuJwy4KvFHJUAuLhLj0hVeq-y10CmRJ1_MPTuNRJLdblSWcXyWYIikIRggQWS0'
  + '4M-QjR7571mX-Lu_eDs8xJVrnNFMVGRmFqf3EFD4QLNjW9JJj0m_prnTv41V_E8AA7MQZ12ip3u5aeOAQqGjVyzdHxvV9lax'
  + 'ta6XWaM8QSTIu_Zav1-aDYExp99nCP4Hw0_Oom5vK5N88DB8VM0mouQi8a8Q","e":"AQAB","x5c":["MIIDYDCCAkigAwI'
  + 'BAgIJAN2X7t+ckntxMA0GCSqGSIb3DQEBCwUAMCkxJzAlBgNVBAMTHkxpdmUgSUQgU1RTIFNpZ25pbmcgUHVibGljIEtleTA'
  + 'eFw0yMTAzMjkyMzM4MzNaFw0yNjAzMjgyMzM4MzNaMCkxJzAlBgNVBAMTHkxpdmUgSUQgU1RTIFNpZ25pbmcgUHVibGljIEt'
  + 'leTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANmu9EsIKiIfFPkoY/1SSRgYXhFZNheMoJjAkbSlAG9YzD+kdY+'
  + 'THOcWqoYM5Vo3JCSNZceK4WtaDS63YPLSQcXZvFfMWaIQjmpyedrgMKHOhRU2N1US2lGUid8wl37icMuCrxRyVALi4S49IVX'
  + 'qvstdApkSdfzD07jUSS3W5UlnF8lmCIpCEYIEFktODPkI0e+e9Zl/i7v3g7PMSVa5zRTFRkZhan9xBQ+ECzY1vSSY9Jv6a50'
  + '7+NVfxPAAOzEGddoqd7uWnjgEKho1cs3R8b1fZWsbWul1mjPEEkyLv2Wr9fmg2BMaffZwj+B8NPzqJubyuTfPAwfFTNJqLkI'
  + 'vGvECAwEAAaOBijCBhzAdBgNVHQ4EFgQU57BsETnF8TctGU87R4N9YxmNWoIwWQYDVR0jBFIwUIAU57BsETnF8TctGU87R4N'
  + '9YxmNWoKhLaQrMCkxJzAlBgNVBAMTHkxpdmUgSUQgU1RTIFNpZ25pbmcgUHVibGljIEtleYIJAN2X7t+ckntxMAsGA1UdDwQ'
  + 'EAwIBxjANBgkqhkiG9w0BAQsFAAOCAQEAcsk+LGlTzSQdnh3mtCBMNCGZCiTYvFcqenwjDf1/c4U+Yi7fxYmAXm7wVLX+GVM'
  + 'xpLPpzMuVOXztGoPMUgWH59CFWhsMvZbIUKsd8xbEKmls1ZIgxRYdagcWTGeBET6XIoF6Ba57BhRCxFPslhIpg27/HnfHtTd'
  + 'GfjRpafNbBYvC/9PL/s2E9U4AklpUn2W19UiJLRFgXGPjYPLW0j1Od0qzHHJ84saclVwvuOrpp75Y+0Du5Z2OrjNF1W4dEWZ'
  + 'MJmmOe73ejAnoiWJI25kQpkd4ooNasw3HIZEJZ6cKctmPJLdvx0tJ8bde4DivtWOeFIwcAkokH2jlHmAOipNETw=="],"iss'
  + 'uer":"https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0"}';

  Check(K.alg = RS256);
end;

procedure TJKWS_TestCase.alg;
begin
  var o: Talg;
  for var i := Low(Talg.Talg_type) to High(Talg.Talg_type) do begin
    o := i;
    CheckEquals(Talg[i], o);
    o := Talg[i];
    CheckTrue(Talg.Talg_type(o) = i);
  end;
end;

procedure TJKWS_TestCase.kty;
begin
  var o: Tkty;
  for var i := Low(Tkty.Tkty_type) to High(Tkty.Tkty_type) do begin
    o := i;
    CheckEquals(Tkty[i], o);
    o := Tkty[i];
    CheckTrue(Tkty.Tkty_type(o) = i);
  end;
end;

procedure TJKWS_TestCase.use;
begin
  var o: Tuse;
  for var i := Low(Tuse.Tuse_type) to High(Tuse.Tuse_type) do begin
    o := i;
    CheckEquals(Tuse[i], o);
    o := Tuse[i];
    CheckTrue(Tuse.Tuse_type(o) = i);
  end;
end;

initialization
  TJKWS_TestCase.ClassName;
end.
