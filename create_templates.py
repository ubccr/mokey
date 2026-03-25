#!/usr/bin/env python3
"""Script to create Solcon email templates."""

import os

templates = {
    "password-reset.html": """<!DOCTYPE html>
<html lang="nl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{{ Translate $.lang "email_template.password_reset_title" }}</title>
<style>
body{margin:0;padding:0;font-family:'Segoe UI',Arial,sans-serif;background-color:#e8ecef;}
a{color:#004080;text-decoration:none;}
table{border-collapse:collapse;}
</style>
</head>
<body>
<table width="100%" cellpadding="0" cellspacing="0" bgcolor="#e8ecef" role="presentation"><tr><td align="center" style="padding:40px 20px;">
<table width="100%" max-width="600" cellpadding="0" cellspacing="0" bgcolor="#ffffff" style="border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,0.08);overflow:hidden;" role="presentation">
<tr><td align="center" style="padding:40px 40px 30px 40px;background-color:#ffffff;text-align:center;border-bottom:1px solid #e1e5eb;">
<a href="{{ $.homepage }}"><img src="{{ $.base_url }}/static/images/solcon-logo.png" alt="Solcon" style="max-width:160px;height:auto;"></a>
</td></tr>
<tr><td style="padding:35px 40px;">
<h1 style="margin:0 0 20px 0;font-size:22px;font-weight:600;color:#003366;">{{ Translate $.lang "email_template.password_reset_greeting" }} {{ $.user.First }},</h1>
<p style="margin:0 0 25px 0;font-size:15px;line-height:1.7;color:#333333;">{{ Translate $.lang "email_template.password_reset_intro_part1" }}{{ $.site_name }}{{ Translate $.lang "email_template.password_reset_intro_part2" }}{{ Translate $.lang "email_template.password_reset_intro_part3" }}{{ $.link_expires }}</p>
<table width="100%" cellpadding="0" cellspacing="0" style="margin:30px 0;background-color:#f5f7fa;border-radius:6px;" role="presentation"><tr><td style="padding:20px 25px;">
<table width="100%" cellpadding="0" cellspacing="0"><tr><td style="padding:8px 0;font-size:14px;color:#666666;border-bottom:1px solid #e1e5eb;"><strong style="color:#003366;">Vervaldatum:</strong> {{ $.link_expires }}</td></tr>
<tr><td style="padding:8px 0 0 0;font-size:14px;color:#666666;"><strong style="color:#003366;">Gebruikersnaam:</strong> {{ $.user.Username }}</td></tr>
</table>
</td></tr></table>
<div style="margin:35px 0;text-align:center;">
<a href="{{ $.link }}" style="display:inline-block;padding:14px 36px;background-color:#003366;color:#ffffff;text-decoration:none;border-radius:4px;font-size:15px;font-weight:500;">{{ Translate $.lang "email_template.password_reset_button" }}</a>
</div>
<p style="margin:0 0 15px 0;font-size:14px;color:#666666;">{{ Translate $.lang "email_template.password_reset_trouble" }}</p>
<p style="margin:0;font-size:13px;color:#004080;word-break:break-all;"><a href="{{ $.link }}" style="color:#004080;text-decoration:underline;">{{ $.link }}</a></p>
<p style="margin:30px 0 0 0;font-size:16px;line-height:1.625;color:#333333;">{{ Translate $.lang "email_template.account_updated_security_notice_part1" }}{{ $.os }}{{ Translate $.lang "email_template.account_updated_security_notice_part2" }}{{ $.browser }}{{ Translate $.lang "email_template.account_updated_security_notice_part3" }}{{ Translate $.lang "email_template.account_updated_security_notice_part4" }}<a href="mailto:{{ $.contact }}" style="color:#004080;">{{ Translate $.lang "email_template.account_updated_security_notice_contact" }}</a>{{ Translate $.lang "email_template.account_updated_security_notice_part5" }}<a href="{{ $.help_url }}" style="color:#004080;">{{ Translate $.lang "email_template.account_updated_security_notice_help" }}</a>{{ Translate $.lang "email_template.account_updated_security_notice_part6" }}</p>
<p style="margin:25px 0 0 0;font-size:16px;color:#333333;">{{ Translate $.lang "closing_part1" }}{{ $.site_name }}{{ Translate $.lang "closing_part2" }}</p>
</td></tr>
<tr><td style="padding:30px 40px;background-color:#f5f7fa;border-top:1px solid #e1e5eb;">
<p style="margin:0 0 15px 0;font-size:14px;color:#003366;font-weight:600;">{{ Translate $.lang "email_template.footer_questions" }}</p>
<p style="margin:0 0 10px 0;font-size:14px;color:#333333;">{{ Translate $.lang "email_template.footer_contact" }}</p>
<p style="margin:0;font-size:14px;color:#333333;"><a href="mailto:noc@solcon.nl" style="color:#004080;text-decoration:none;">noc@solcon.nl</a>&nbsp;&nbsp;|&nbsp;&nbsp;<a href="tel:+31880032210" style="color:#004080;text-decoration:none;">+31 88 003 2210</a></p>
<p style="margin:25px 0 0 0;font-size:12px;color:#666666;">{{ Translate $.lang "email_template.footer_sent_to" }}<br><strong>{{ $.user.Username }}</strong></p>
</td></tr>
<tr><td style="padding:20px 40px;background-color:#003366;text-align:center;">
<p style="margin:0;font-size:13px;color:#ffffff;letter-spacing:1px;font-weight:500;">SOLCON</p>
<p style="margin:5px 0 0 0;font-size:11px;color:rgba(255,255,255,0.7);">Internetdiensten B.V.</p>
</td></tr>
</table>
</td></tr>
</table>
</body>
</html>""",
    "account-updated.html": """<!DOCTYPE html>
<html lang="nl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{{ Translate $.lang "email_template.account_updated_title" }}</title>
<style>
body{margin:0;padding:0;font-family:'Segoe UI',Arial,sans-serif;background-color:#e8ecef;}
a{color:#004080;text-decoration:none;}
table{border-collapse:collapse;}
</style>
</head>
<body>
<table width="100%" cellpadding="0" cellspacing="0" bgcolor="#e8ecef" role="presentation"><tr><td align="center" style="padding:40px 20px;">
<table width="100%" max-width="600" cellpadding="0" cellspacing="0" bgcolor="#ffffff" style="border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,0.08);overflow:hidden;" role="presentation">
<tr><td align="center" style="padding:40px 40px 30px 40px;background-color:#ffffff;text-align:center;border-bottom:1px solid #e1e5eb;">
<a href="{{ $.homepage }}"><img src="{{ $.base_url }}/static/images/solcon-logo.png" alt="Solcon" style="max-width:160px;height:auto;"></a>
</td></tr>
<tr><td style="padding:35px 40px;">
<h1 style="margin:0 0 20px 0;font-size:22px;font-weight:600;color:#003366;">{{ Translate $.lang "email_template.account_updated_greeting" }} {{ $.user.First }},</h1>
<p style="margin:0 0 25px 0;font-size:15px;line-height:1.7;color:#333333;">{{ Translate $.lang "email_template.account_updated_body_part1" }}{{ $.site_name }}{{ Translate $.lang "email_template.account_updated_body_part2" }}</p>
<table width="100%" cellpadding="0" cellspacing="0" style="margin:30px 0;background-color:#f5f7fa;border-radius:6px;" role="presentation"><tr><td style="padding:20px 25px;">
<table width="100%" cellpadding="0" cellspacing="0"><tr><td style="padding:8px 0;font-size:14px;color:#666666;border-bottom:1px solid #e1e5eb;"><strong style="color:#003366;">Wijziging:</strong> {{ $.event }}</td></tr>
</table>
</td></tr></table>
<p style="margin:0;font-size:16px;line-height:1.625;color:#333333;">{{ Translate $.lang "email_template.account_updated_security_notice_part1" }}{{ $.os }}{{ Translate $.lang "email_template.account_updated_security_notice_part2" }}{{ $.browser }}{{ Translate $.lang "email_template.account_updated_security_notice_part3" }}{{ Translate $.lang "email_template.account_updated_security_notice_part4" }}<a href="mailto:{{ $.contact }}" style="color:#004080;">{{ Translate $.lang "email_template.account_updated_security_notice_contact" }}</a>{{ Translate $.lang "email_template.account_updated_security_notice_part5" }}<a href="{{ $.help_url }}" style="color:#004080;">{{ Translate $.lang "email_template.account_updated_security_notice_help" }}</a>{{ Translate $.lang "email_template.account_updated_security_notice_part6" }}</p>
<p style="margin:25px 0 0 0;font-size:16px;color:#333333;">{{ Translate $.lang "email_template.account_updated_signature" }}</p>
</td></tr>
<tr><td style="padding:30px 40px;background-color:#f5f7fa;border-top:1px solid #e1e5eb;">
<p style="margin:0 0 15px 0;font-size:14px;color:#003366;font-weight:600;">{{ Translate $.lang "email_template.footer_questions" }}</p>
<p style="margin:0 0 10px 0;font-size:14px;color:#333333;">{{ Translate $.lang "email_template.footer_contact" }}</p>
<p style="margin:0;font-size:14px;color:#333333;"><a href="mailto:noc@solcon.nl" style="color:#004080;text-decoration:none;">noc@solcon.nl</a>&nbsp;&nbsp;|&nbsp;&nbsp;<a href="tel:+31880032210" style="color:#004080;text-decoration:none;">+31 88 003 2210</a></p>
</td></tr>
<tr><td style="padding:20px 40px;background-color:#003366;text-align:center;">
<p style="margin:0;font-size:13px;color:#ffffff;letter-spacing:1px;font-weight:500;">SOLCON</p>
<p style="margin:5px 0 0 0;font-size:11px;color:rgba(255,255,255,0.7);">Internetdiensten B.V.</p>
</td></tr>
</table>
</td></tr>
</table>
</body>
</html>""",
    "account-verify.html": """<!DOCTYPE html>
<html lang="nl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{{ Translate $.lang "email_template.account_verify_title" }}</title>
<style>
body{margin:0;padding:0;font-family:'Segoe UI',Arial,sans-serif;background-color:#e8ecef;}
a{color:#004080;text-decoration:none;}
table{border-collapse:collapse;}
</style>
</head>
<body>
<table width="100%" cellpadding="0" cellspacing="0" bgcolor="#e8ecef" role="presentation"><tr><td align="center" style="padding:40px 20px;">
<table width="100%" max-width="600" cellpadding="0" cellspacing="0" bgcolor="#ffffff" style="border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,0.08);overflow:hidden;" role="presentation">
<tr><td align="center" style="padding:40px 40px 30px 40px;background-color:#ffffff;text-align:center;border-bottom:1px solid #e1e5eb;">
<a href="{{ $.homepage }}"><img src="{{ $.base_url }}/static/images/solcon-logo.png" alt="Solcon" style="max-width:160px;height:auto;"></a>
</td></tr>
<tr><td style="padding:35px 40px;">
<h1 style="margin:0 0 20px 0;font-size:22px;font-weight:600;color:#003366;">{{ Translate $.lang "email_template.account_verify_greeting" }} {{ $.user.First }},</h1>
<p style="margin:0 0 25px 0;font-size:15px;line-height:1.7;color:#333333;">{{ Translate $.lang "email_template.account_verify_intro_part1" }}{{ $.site_name }}{{ Translate $.lang "email_template.account_verify_intro_part2" }}</p>
<div style="margin:35px 0;text-align:center;">
<a href="{{ $.link }}" style="display:inline-block;padding:14px 36px;background-color:#003366;color:#ffffff;text-decoration:none;border-radius:4px;font-size:15px;font-weight:500;">{{ Translate $.lang "email_template.account_verify_button" }}</a>
</div>
<p style="margin:0 0 15px 0;font-size:14px;color:#666666;">{{ Translate $.lang "email_template.password_reset_trouble" }}</p>
<p style="margin:0;font-size:13px;color:#004080;word-break:break-all;"><a href="{{ $.link }}" style="color:#004080;text-decoration:underline;">{{ $.link }}</a></p>
<p style="margin:25px 0 0 0;font-size:16px;color:#333333;">{{ Translate $.lang "closing_part1" }}{{ $.site_name }}{{ Translate $.lang "closing_part2" }}</p>
</td></tr>
<tr><td style="padding:30px 40px;background-color:#f5f7fa;border-top:1px solid #e1e5eb;">
<p style="margin:0 0 15px 0;font-size:14px;color:#003366;font-weight:600;">{{ Translate $.lang "email_template.footer_questions" }}</p>
<p style="margin:0 0 10px 0;font-size:14px;color:#333333;">{{ Translate $.lang "email_template.footer_contact" }}</p>
<p style="margin:0;font-size:14px;color:#333333;"><a href="mailto:noc@solcon.nl" style="color:#004080;text-decoration:none;">noc@solcon.nl</a>&nbsp;&nbsp;|&nbsp;&nbsp;<a href="tel:+31880032210" style="color:#004080;text-decoration:none;">+31 88 003 2210</a></p>
</td></tr>
<tr><td style="padding:20px 40px;background-color:#003366;text-align:center;">
<p style="margin:0;font-size:13px;color:#ffffff;letter-spacing:1px;font-weight:500;">SOLCON</p>
<p style="margin:5px 0 0 0;font-size:11px;color:rgba(255,255,255,0.7);">Internetdiensten B.V.</p>
</td></tr>
</table>
</td></tr>
</table>
</body>
</html>""",
    "welcome.html": """<!DOCTYPE html>
<html lang="nl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{{ Translate $.lang "email_template.welcome_title" }}</title>
<style>
body{margin:0;padding:0;font-family:'Segoe UI',Arial,sans-serif;background-color:#e8ecef;}
a{color:#004080;text-decoration:none;}
table{border-collapse:collapse;}
</style>
</head>
<body>
<table width="100%" cellpadding="0" cellspacing="0" bgcolor="#e8ecef" role="presentation"><tr><td align="center" style="padding:40px 20px;">
<table width="100%" max-width="600" cellpadding="0" cellspacing="0" bgcolor="#ffffff" style="border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,0.08);overflow:hidden;" role="presentation">
<tr><td align="center" style="padding:40px 40px 30px 40px;background-color:#ffffff;text-align:center;border-bottom:1px solid #e1e5eb;">
<a href="{{ $.homepage }}"><img src="{{ $.base_url }}/static/images/solcon-logo.png" alt="Solcon" style="max-width:160px;height:auto;"></a>
</td></tr>
<tr><td style="padding:35px 40px;">
<h1 style="margin:0 0 20px 0;font-size:22px;font-weight:600;color:#003366;">{{ Translate $.lang "email_template.welcome_greeting" }} {{ $.user.First }}!</h1>
<p style="margin:0 0 25px 0;font-size:15px;line-height:1.7;color:#333333;">{{ Translate $.lang "email_template.welcome_intro_part1" }}{{ $.site_name }}{{ Translate $.lang "email_template.welcome_intro_part2" }}</p>
<div style="margin:35px 0;text-align:center;">
<a href="{{ $.getting_started_url }}" style="display:inline-block;padding:14px 36px;background-color:#003366;color:#ffffff;text-decoration:none;border-radius:4px;font-size:15px;font-weight:500;">{{ Translate $.lang "email_template.welcome_button" }}</a>
</div>
<p style="margin:0 0 25px 0;font-size:15px;line-height:1.7;color:#333333;">{{ Translate $.lang "email_template.welcome_note_part1" }}{{ $.base_url }}{{ Translate $.lang "email_template.welcome_note_part2" }}{{ $.user.Username }}</p>
<p style="margin:0;font-size:16px;color:#333333;">{{ Translate $.lang "closing_part1" }}{{ $.site_name }}{{ Translate $.lang "closing_part2" }}</p>
</td></tr>
<tr><td style="padding:30px 40px;background-color:#f5f7fa;border-top:1px solid #e1e5eb;">
<p style="margin:0 0 15px 0;font-size:14px;color:#003366;font-weight:600;">{{ Translate $.lang "email_template.footer_questions" }}</p>
<p style="margin:0 0 10px 0;font-size:14px;color:#333333;">{{ Translate $.lang "email_template.footer_contact" }}</p>
<p style="margin:0;font-size:14px;color:#333333;"><a href="mailto:noc@solcon.nl" style="color:#004080;text-decoration:none;">noc@solcon.nl</a>&nbsp;&nbsp;|&nbsp;&nbsp;<a href="tel:+31880032210" style="color:#004080;text-decoration:none;">+31 88 003 2210</a></p>
</td></tr>
<tr><td style="padding:20px 40px;background-color:#003366;text-align:center;">
<p style="margin:0;font-size:13px;color:#ffffff;letter-spacing:1px;font-weight:500;">SOLCON</p>
<p style="margin:5px 0 0 0;font-size:11px;color:rgba(255,255,255,0.7);">Internetdiensten B.V.</p>
</td></tr>
</table>
</td></tr>
</table>
</body>
</html>""",
}


def create_templates():
    base_dir = os.path.join(
        os.path.dirname(__file__), "solcon-templates", "templates", "email"
    )
    os.makedirs(base_dir, exist_ok=True)

    for filename, content in templates.items():
        path = os.path.join(base_dir, filename)
        with open(path, "w") as f:
            f.write(content)
        print(f"Created: {path}")

    print("\\nAll templates created successfully!")


if __name__ == "__main__":
    create_templates()
