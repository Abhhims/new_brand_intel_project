/*
  Phishing / credential-harvest indicators for the email module (D-28).
  Conservative rules: each requires several co-occurring signals so that ordinary marketing email does not match.
  These run against email bodies and HTML/script attachments only; nothing is executed.
*/

rule credential_harvest_form
{
    meta:
        description = "HTML asking for a password/OTP/card with urgency language"
        severity = "suspicious"
    strings:
        $form = "<form" nocase
        $pw = "type=\"password\"" nocase
        $pw2 = "type='password'" nocase
        $u1 = "verify your account" nocase
        $u2 = "account has been suspended" nocase
        $u3 = "confirm your identity" nocase
        $u4 = "unusual activity" nocase
        $c1 = "card number" nocase
        $c2 = "one time password" nocase
        $c3 = "otp" nocase
    condition:
        $form and ($pw or $pw2) and (any of ($u*) or any of ($c*))
}

rule brand_login_lookalike
{
    meta:
        description = "Login form posting credentials to an off-site handler"
        severity = "suspicious"
    strings:
        $pw = "type=\"password\"" nocase
        $a1 = "action=\"http" nocase
        $a2 = "formaction=" nocase
        $b1 = "sign in" nocase
        $b2 = "log in" nocase
        $b3 = "login" nocase
    condition:
        $pw and any of ($a*) and any of ($b*)
}

rule obfuscated_script_in_email
{
    meta:
        description = "Heavily obfuscated JavaScript inside an email body / HTML attachment"
        severity = "suspicious"
    strings:
        $s1 = "eval(" nocase
        $s2 = "unescape(" nocase
        $s3 = "fromCharCode" nocase
        $s4 = "atob(" nocase
        $s5 = "document.write(unescape" nocase
    condition:
        2 of them
}
