unit JWT.IPWorksEncrypt.TestCase;

interface

uses
  TestFramework,
  JWT;

type
  TTestCase_JWT_IPWorksEncrypt = class(TTestCase)
  const RSA_PrivateKey =
    '-----BEGIN RSA PRIVATE KEY-----' + sLineBreak
  + 'MIIEogIBAAKCAQEAxl67D/+6fzIl9uf84tr6vApGNuJ4FMHD54qYLnzPkB9XP9ME' + sLineBreak
  + 'GlGNQUt7X6Wj4RvPAJReEaPpNVe0Y/UMwG4KZA6NrwPWVtGKre1YbnltxOpRj1Ro' + sLineBreak
  + 'MTV2PC1AAIdxNNM3lZ3ATefCbkXFRb5ejZKo3PjAUjRFgJkgtIgPd0E7bov0IOJB' + sLineBreak
  + 'j74MSDMNmFRRoaiMLmzBAvWpTkntYp+Y+EyIr+JI1Nv8pU2TutRQaVtAzi4UyYPf' + sLineBreak
  + 'pqKUn/kOMEY37kuESGRwxZQGEfMJPwagFw1QNgtHHE/up0nF49QDA0I+gTu2zw3r' + sLineBreak
  + '4juziAFWlauCZP135+qlGMvCz/BJBnlsH8sLnQIDAQABAoIBACSO5M6oBIjYhyKf' + sLineBreak
  + '0n1Eeh0Zj6MhzZuVsjMD2dQHcIFRJVU/4GuxR+UWsiAIeNFNvLKQpV1+5cXM6hPZ' + sLineBreak
  + '34W/Qe76t6XfgSry5ynyqe+CNXaq8GkH10PqZGXmuPrf+z8PBhluvzgcVDraZObb' + sLineBreak
  + 'lLVmp/RBa8A6nex7TAm5YZBK11ch5CRa6+4HwPKQRDM37e4qBh/FN4TzH1lNZVQX' + sLineBreak
  + 'L1Q+6FvT1N7+NwPE90AVgZSDiMcDMaWolXLrjkKsbUudBDCV6tr9KPSmIRp/JYhG' + sLineBreak
  + 'JNVVnq84aE06YxUyQEBLrda04BFkUBqoWr2AkcjmMsX7fzwkzdcEDJhEjZgUCc2w' + sLineBreak
  + 'YYgQdQECgYEA/umlStT4/L5o9iQOV+/1nuMJq4dPi8s3IzmIZT+kFLWyYc6DW2P0' + sLineBreak
  + 'aL4uiD2vDN3S6kekRbksbwXiZaM05t/MkiVjjVap75oM/LhkJIlfxmGajk/lB3c2' + sLineBreak
  + 'ktJKPgfCQE+0tMM6/N2vp22XMUGkRcPAtXmkHj4M7OW+P0/x/qH+SH0CgYEAxzdX' + sLineBreak
  + 'v7plG94JiPI28c6yB9XvaeFU4zcXvG/JxAhkBVz/LiO+HTUOKAongYERMY2rkWo2' + sLineBreak
  + '3HMkTpbaKru70WIL6H6nGu1i8zpiQRpqwdlWIKPAjfLk5ezFoqw5kAcZmho0RW1w' + sLineBreak
  + '5VAv/SZ/GA5U3x9kevaQuDDm+6Ep0Qq2wLIcWaECgYAKxzBA+L5KWXawqZedqjy1' + sLineBreak
  + 'ah4XjZIUdBQxvhYBSe6THZecQRIWxCQqZZgsFIeZQKvRUhQlCo5RZ2tKJttuw5mv' + sLineBreak
  + 'uDr8V+S5h8byzI0XamONTMUvLTue1DCPhqqy8rsI4xXd6r9Mv8bUinKxF3htprg4' + sLineBreak
  + 'NBt3V+JOBezEWon93TWWNQKBgCANF2ERbBL/tikCTzS4PIxmLw6p4i5sPrVihuOz' + sLineBreak
  + 'NeRnAec6eOvaDV0DxTdgvJNsZ54NqKXvIHhEbPVTHvShAal2NwxuBO19BzHSPjrR' + sLineBreak
  + '7Llznxc3bPxRC7sQWnKBsezJKn/BC9jY/d+MwgXsyFrdgh0GbmIz+/WgCEpJnv2B' + sLineBreak
  + 'qm4BAoGAez1ke8owOzs0Mmug/8Ktd6o7sMCXV8rJx6jvv6Xil13zfq7VfxNI0Dsf' + sLineBreak
  + '9EGJ6cpnabohEykI+rSaZcpGCu/x44RQZ68umEdlxK+sO5jeIN3wV4J61+YZfD9Z' + sLineBreak
  + 'FI7toHWL9RMH6+GkhvIZnEtiQBRAfexsRpew/J/+ujooe9rKtyw=' + sLineBreak
  + '-----END RSA PRIVATE KEY-----';
  const RSA_PublicKey =
    '-----BEGIN PUBLIC KEY-----' + sLineBreak
  + 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxl67D/+6fzIl9uf84tr6' + sLineBreak
  + 'vApGNuJ4FMHD54qYLnzPkB9XP9MEGlGNQUt7X6Wj4RvPAJReEaPpNVe0Y/UMwG4K' + sLineBreak
  + 'ZA6NrwPWVtGKre1YbnltxOpRj1RoMTV2PC1AAIdxNNM3lZ3ATefCbkXFRb5ejZKo' + sLineBreak
  + '3PjAUjRFgJkgtIgPd0E7bov0IOJBj74MSDMNmFRRoaiMLmzBAvWpTkntYp+Y+EyI' + sLineBreak
  + 'r+JI1Nv8pU2TutRQaVtAzi4UyYPfpqKUn/kOMEY37kuESGRwxZQGEfMJPwagFw1Q' + sLineBreak
  + 'NgtHHE/up0nF49QDA0I+gTu2zw3r4juziAFWlauCZP135+qlGMvCz/BJBnlsH8sL' + sLineBreak
  + 'nQIDAQAB' + sLineBreak
  + '-----END PUBLIC KEY-----';
  private
    function Get_Sample: TJWT;
  public
    class constructor Create;
  published
    procedure ES256;
    procedure ES384;
    procedure ES512;
    procedure PS256;
    procedure PS384;
    procedure PS512;
    procedure RS256;
    procedure RS384;
    procedure RS512;
  end;

implementation

uses
  JWKS, JWT.ES, JWT.RS;

class constructor TTestCase_JWT_IPWorksEncrypt.Create;
begin
  RegisterTest(Suite);
end;

procedure TTestCase_JWT_IPWorksEncrypt.ES256;
begin
  var J: TJWT := Get_Sample;
  J.Sign(Talg.Talg_type.ES256,
    '-----BEGIN EC PRIVATE KEY-----'#10
  + 'MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg2gKXqdRFM9aXGpx9'#10
  + 'iZQleHGosURMUWurcQU1ZTa1lv2hRANCAATGbupWFeUQDUl019GAC19O52J43Xdq'#10
  + 'El4umYY7rYI84q4xxwNKQ72qQNDufBezt7fSd76dlctQBXO/pBluCb0P'#10
  + '-----END EC PRIVATE KEY-----'#10
  );
  CheckTrue(J);

  var Token := 'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiIsImtpZCI6IjEifQ.'
             + 'eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImN1c3RvbTEiOiJhZG1pbiIsImN1c3RvbTIiOnRydWUsImN1c3RvbTMiOjk5fQ.'
             + '8kEUZxzjG2gJ5VYIxt6_bdWoCKWudrCUiQ1i3IlCBQOr-t97LokVR-OznyNbkI5FCDkFuYRHDDKjMD1h3qrHqg';

  J := Token;
  CheckFalse(J);
  CheckTrue(J.Validate(
    '-----BEGIN PUBLIC KEY-----'#10
  + 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAExm7qVhXlEA1JdNfRgAtfTudieN13'#10
  + 'ahJeLpmGO62CPOKuMccDSkO9qkDQ7nwXs7e30ne+nZXLUAVzv6QZbgm9Dw=='#10
  + '-----END PUBLIC KEY-----'#10
  ));
  CheckTrue(J);
end;

procedure TTestCase_JWT_IPWorksEncrypt.ES384;
begin
  var J: TJWT := Get_Sample;
  J.Sign(Talg.Talg_Type.ES384,
    '-----BEGIN EC PRIVATE KEY-----'#10
  + 'MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDBQvNZuQdrSyjBs1SZ2'#10
  + 'mM/YSm6wZ47XEVdZmFZ9UK3an/aGj+1e/UEAlahQqlvTqDqhZANiAASfo7q13krr'#10
  + 'CvicRHwwlnHuxcNQZz0INqlhsZd4vBNv6N/wLs9O/bdiUzVPd7BND9hLFVfuvJ1p'#10
  + 'nCy5kRM+90BWmVxfVJc1FTpnabot+8ZI2qzjqxYZUMBlO0QEizXzdxo='#10
  + '-----END EC PRIVATE KEY-----'#10
  );
  CheckTrue(J);

  var Token := 'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzM4NCIsImtpZCI6IjEifQ.'
             + 'eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImN1c3RvbTEiOiJhZG1pbiIsImN1c3RvbTIiOnRydWUsImN1c3RvbTMiOjk5fQ.'
             + '_F0ojeVbnpgix-P6EqQPakkbWkERb-VOHbtiPacccAxFH3aEpWs_5jVd_ObEn0v2MZ_25u14ASaR4h4mVB3RzxsRvGcQV9gxFxdInNVwUlApd3jFm8po7K4fgN4qL_1O';

  J := Token;
  CheckFalse(J);
  CheckTrue(J.Validate(
    '-----BEGIN PUBLIC KEY-----'#10
  + 'MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEn6O6td5K6wr4nER8MJZx7sXDUGc9CDap'#10
  + 'YbGXeLwTb+jf8C7PTv23YlM1T3ewTQ/YSxVX7rydaZwsuZETPvdAVplcX1SXNRU6'#10
  + 'Z2m6LfvGSNqs46sWGVDAZTtEBIs183ca'#10
  + '-----END PUBLIC KEY-----'
  ));
  CheckTrue(J);
end;

procedure TTestCase_JWT_IPWorksEncrypt.ES512;
begin
  var J: TJWT := Get_Sample;
  J.Sign(Talg.Talg_Type.ES512,
    '-----BEGIN EC PRIVATE KEY-----'#10
  + 'MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIBML3/f41ilzC9OKK0'#10
  + 'dC57/2ywO7P6m/TpgO1DmXbIvxAi3Ovr5wPH/h7QaQKPPvx1baEBNfXlFHKHf5lB'#10
  + 'wXChuMuhgYkDgYYABAHJc0Zct3kelKf4iYE5Pw51bAGU4QdslIux4tYJyWuxh2Bk'#10
  + 'NK9ciMHcAc7A+CjyNYwfc8sJiwoj/oFGHFwdPhJU1AE+P1n1T48DUaMbz4SPtzhB'#10
  + 'M2oTWmEEmV+kzCilw1lxjSPeSIYtnJD1WuSXO2gjrSHF/UTQbsLB0Z+rQTgK41LP'#10
  + '/Q=='#10
  + '-----END EC PRIVATE KEY-----'#10
  );
  CheckTrue(J);

  var Token := 'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzUxMiIsImtpZCI6IjEifQ.'
             + 'eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImN1c3RvbTEiOiJhZG1pbiIsImN1c3RvbTIiOnRydWUsImN1c3RvbTMiOjk5fQ.'
             + 'Ad-rC1KbmjPx4Ah-rYvYd2oHj87BCcnACCaxEzJJB0PXRu0k46w-68zlRTIm65sNl3KmncmBe2cF3rnaWGBE1PBEAfW2Nn3k9X05aWgGLzdzU_vCau5_pa2-CHcar5vTCUwJ9vxcX3binfne6iMCsAL2pajJFh1h1uK8XT6Mhr1OGlzi';

  J := Token;
  CheckFalse(J);
  CheckTrue(J.Validate(
    '-----BEGIN PUBLIC KEY-----'#10
  + 'MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQByXNGXLd5HpSn+ImBOT8OdWwBlOEH'#10
  + 'bJSLseLWCclrsYdgZDSvXIjB3AHOwPgo8jWMH3PLCYsKI/6BRhxcHT4SVNQBPj9Z'#10
  + '9U+PA1GjG8+Ej7c4QTNqE1phBJlfpMwopcNZcY0j3kiGLZyQ9VrklztoI60hxf1E'#10
  + '0G7CwdGfq0E4CuNSz/0='#10
  + '-----END PUBLIC KEY-----'#10
  ));
  CheckTrue(J);
end;

function TTestCase_JWT_IPWorksEncrypt.Get_Sample: TJWT;
begin
  Result.Header.kid.ValueString := '1';
  Result.Claims.iss.ValueString := 'joe';
  Result.Claims.exp.ValueNumeric := 1300819380;
  Result.Claims.Add('custom1', 'admin');
  Result.Claims.Add('custom2', true);
  Result.Claims.Add('custom3', 99);
end;

procedure TTestCase_JWT_IPWorksEncrypt.PS256;
begin
  var J: TJWT := Get_Sample;
  J.Sign(Talg.Talg_Type.PS256, RSA_PrivateKey);
  CheckTrue(J);

  var Token := 'eyJ0eXAiOiJKV1QiLCJhbGciOiJQUzI1NiIsImtpZCI6IjEifQ.'
             + 'eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImN1c3RvbTEiOiJhZG1pbiIsImN1c3RvbTIiOnRydWUsImN1c3RvbTMiOjk5fQ.'
             + 'RVMi1G274gVbdPzTL4xO21bgVqrPCYZPVgoU7I6nzQLHLczpc2pgjy0IG0v5Y__7AMAf26U89bUhE5BaPlCzzeUZlUhDuLv6jcIYXJE'
             + 'bmIfoMeaWeFG2SfmHqMfrBlGLDG8FhXFYnYbiEUcvWdYGBg7TwD_E0xR-pvCb3xfQMaG66OCwInuv_bJ5rXa-pWheHdhivhFA8ieKwd_lXRiRL0YwnQXVPGv14b_4W5S_WFb59f8O2-T1KNQ5rvWkTO0If7eO3XpApy_JxdEyfuZuYQ0zoRKNQCnAl3dvaz2XXuuzRjOdNiGnwsTtBbmt464SCDRm2Oa1nStnrrFMOQjDiQ';

  J := Token;
  CheckFalse(J);
  CheckTrue(J.Validate(RSA_PublicKey));
  CheckTrue(J);
end;

procedure TTestCase_JWT_IPWorksEncrypt.PS384;
begin
  var J: TJWT := Get_Sample;
  J.Sign(Talg.Talg_Type.PS384, RSA_PrivateKey);
  CheckTrue(J);

  var Token := 'eyJ0eXAiOiJKV1QiLCJhbGciOiJQUzM4NCIsImtpZCI6IjEifQ.'
             + 'eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImN1c3RvbTEiOiJhZG1pbiIsImN1c3RvbTIiOnRydWUsImN1c3RvbTMiOjk5fQ.'
             + 'PV0o6BpUw9dqhPBh2iKpmEAxzGPjh9pabwxKRKqtFFkXF2VGz_ZrwucmdeikGLxplueD2gm_VhVElpE3TQiqaj9q96RasxlihhKBp-_'
             + 'DD2PkewB8atQ7Nj2Li6HDf6c1gA4JenCLko2PHehJQg9P2iERYOcGrMqHWKKT7AJhoiTBh9sSS970fJ-7zi6F4mWh32MPraFxPfWb2TOGecR9RYGP6PTy6mZlCr96vgFzDpZcC6FHAEF-T_WPlMq-uBHGgopGt4JEaV4KvgqsQ8RpQXamvS2FRYDqxHb1OkhRJoDTQ7Qh56Z5xxTCxxEe8VlIcm0HzmX8nBye-QrE1Z8HPw';

  J := Token;
  CheckFalse(J);
  CheckTrue(J.Validate(RSA_PublicKey));
  CheckTrue(J);
end;

procedure TTestCase_JWT_IPWorksEncrypt.PS512;
begin
  var J: TJWT := Get_Sample;
  J.Sign(Talg.Talg_Type.PS512, RSA_PrivateKey);
  CheckTrue(J);

  var Token := 'eyJ0eXAiOiJKV1QiLCJhbGciOiJQUzUxMiIsImtpZCI6IjEifQ.'
             + 'eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImN1c3RvbTEiOiJhZG1pbiIsImN1c3RvbTIiOnRydWUsImN1c3RvbTMiOjk5fQ.'
             + 'chVIq_bk8yk9RB0zd5uadroKStZV4pIS6cZ3OqqIOvvZVWK0NoWFFgu2LpyDQ6bGjAUuYhaBlHkm4Cd3yLQ_Je6VPir-FkY5mZ1HS2m'
             + 'XILUoGvbaT0XrIUIuZegjLguWiJRQPrsacF7_tR5jdXpBQBn26WeZvFDLtFAiNcaYl6zaM0a_cNtOhYtDAmnn32K1hhnU4II0QAEml-1Sz3dIlaDgdB_WdZ7sxprGrArvURBmJAAgnyL75Q3l9RQ1lCg5gdOj05Gee26_ma_w0dEDBY1iq1uxMUnntvL9ZbTtFSpLR0wVm0mOzoTh4Zl1nM_laseJEp474Iv-wecnqBUQJA';

  J := Token;
  CheckFalse(J);
  CheckTrue(J.Validate(RSA_PublicKey));
  CheckTrue(J);
end;

procedure TTestCase_JWT_IPWorksEncrypt.RS256;
begin
  var J: TJWT := Get_Sample;
  var Token := 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjEifQ.'
             + 'eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImN1c3RvbTEiOiJhZG1pbiIsImN1c3RvbTIiOnRydWUsImN1c3RvbTMiOjk5fQ.'
             + 'd7fCFWaWw6mlYh1Xg1JuQaTVGErT15hoZDKs-_RV4JtMFVOaUZXr71KH_qAcFQWYCBMRsljdBGaDAVteO3Cbh_jCbCFGZQbqS04dT50'
             + '34ITXmR-kdWDq5hOiBgB-OY8TXC0MkO0aPnMZZr3cwNmjCpAEu5TIHpVsh0QYiUbX1E1YXP7V-jba21aw3mrAYAK6GYni0QxUBP-OIY69opl-CIxCovPkamEA6fSxvTCUOj3cyYPPl9-Y4CK8jT8wIZREDbfNHVR2kDc4bDzMgGaUCqwTvgJH2NeAmkNnJDcFzYNa0Q1QexgqjiB9KITBsNBMdE2SHozmgLyMCKeR93yr1g';

  CheckEquals(Token, J.Sign(Talg.Talg_Type.RS256, RSA_PrivateKey));
  status(J);
  CheckEquals(Token, J);

  J := Token;
  CheckFalse(J);
  CheckTrue(J.Validate(RSA_PublicKey));
  CheckTrue(J);
end;

procedure TTestCase_JWT_IPWorksEncrypt.RS384;
begin
  var J: TJWT := Get_Sample;
  var Token := 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzM4NCIsImtpZCI6IjEifQ.'
             + 'eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImN1c3RvbTEiOiJhZG1pbiIsImN1c3RvbTIiOnRydWUsImN1c3RvbTMiOjk5fQ.'
             + 'YM4Wp7tCt6p2-RDwIIWznALOoTEoDBPVJWOtIqsaeOvV8TMHK6JLs8clvewZeIw781UlcX_-ZRpOhG9TdrxMZ6NRsAlK4WP3067fKt6'
             + 'LR8aNhSKCqaW4NrgS_b1A5Xi-M_nVZQJinDeofI8paqOspw4NF5cbQE-T0C_lmoz6ta4kf9z_sCq-9AAK0gopBYCkIwd0cOc9uqxlWett5zL11sieKVR1K8ba0QTl7VFmWk0eB63ptIxxkYp7YdHBonqAIW60tDsAZI-4lVdmcy600839ZnTHOa-5gt9aeBgg_rQIalMdUrC8KSuK1YVhzEGoIWx3RhfZyoOKgW0aBMKYOA';
  CheckEquals(Token, J.Sign(Talg.Talg_Type.RS384, RSA_PrivateKey));
  status(J);
  CheckEquals(Token, J);

  J := Token;
  CheckFalse(J);
  CheckTrue(J.Validate(RSA_PublicKey));
  CheckTrue(J);
end;

procedure TTestCase_JWT_IPWorksEncrypt.RS512;
begin
  var J: TJWT := Get_Sample;
  var Token := 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzUxMiIsImtpZCI6IjEifQ.'
             + 'eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImN1c3RvbTEiOiJhZG1pbiIsImN1c3RvbTIiOnRydWUsImN1c3RvbTMiOjk5fQ.'
             + 'ug112TY1Ph3kR2hM-JvGZKwnXIieemAMQAhMjBO3Pu4nwlAiErz9_VLLvbno8ooRuUhKiqdrSDpo4RxCcpcxxLw4-69KtBMCzjTRAAZ'
             + 'C_9HuE4viSYd_3ZL3qpyjTh0PIEH9_9LB3bnxLU2feLE5rDBoqUtnetSLhQyAJiBlvU01OFQvVpScBeEDnDqeVACrpzDBUFUw0T7GzKY0jEcSN5JaEvdOpqdNZWXUcwFG-6kpdturpmPk5aA9DpAxEA0vqlE1t9YiOW3Rq82zlmCB8Oxxw_IfredEUqM1Wps4PVRTjCSbqJr3liqvalELFFTumw6vr__O6XMa2ASkFfcGAA';

  CheckEquals(Token, J.Sign(Talg.Talg_Type.RS512, RSA_PrivateKey));
  status(J);
  CheckEquals(Token, J);

  J := Token;
  CheckFalse(J);
  CheckTrue(J.Validate(RSA_PublicKey));
  CheckTrue(J);
end;

initialization
  TTestCase_JWT_IPWorksEncrypt.ClassName;
end.
