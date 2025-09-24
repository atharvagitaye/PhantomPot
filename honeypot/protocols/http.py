import http.server
import socketserver

import json
import time
from honeypot.loggers.file_logger import FileLogger


class HTTPHoneypotHandler(http.server.BaseHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        self.logger = FileLogger("logs/attacks.json")
        super().__init__(*args, **kwargs)

    def log_attack(self, service, data=None, payload=None):
        event_data = {
            "method": self.command,
            "path": self.path,
            "headers": dict(self.headers),
        }
        if self.command in ['POST', 'PUT']:
            event_data["payload"] = payload if payload is not None else ""
        else:
            event_data["payload"] = ""
        if data:
            event_data.update(data)
        self.logger.log_event(
            service=service,
            src_ip=self.client_address[0],
            src_port=self.client_address[1],
            data=event_data
        )

    def do_GET(self):
        self.log_attack("http")
        # Serve WordPress wp-admin login page for any path
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        
        # Determine if it's wp-admin or wp-login path for authentic WordPress behavior
        is_admin_path = '/wp-admin' in self.path or '/wp-login' in self.path
        
        wordpress_login = '''<!DOCTYPE html>
<html lang="en-US">
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
    <title>Log In &lsaquo; WordPress &mdash; WordPress</title>
    <link rel='dns-prefetch' href='//fonts.googleapis.com' />
    <link rel='dns-prefetch' href='//s.w.org' />
    <meta name='robots' content='max-image-preview:large' />
    <link rel='stylesheet' id='dashicons-css' href='/wp-includes/css/dashicons.min.css?ver=6.3.1' type='text/css' media='all' />
    <link rel='stylesheet' id='buttons-css' href='/wp-includes/css/buttons.min.css?ver=6.3.1' type='text/css' media='all' />
    <link rel='stylesheet' id='forms-css' href='/wp-admin/css/forms.min.css?ver=6.3.1' type='text/css' media='all' />
    <link rel='stylesheet' id='l10n-css' href='/wp-admin/css/l10n.min.css?ver=6.3.1' type='text/css' media='all' />
    <link rel='stylesheet' id='login-css' href='/wp-admin/css/login.min.css?ver=6.3.1' type='text/css' media='all' />
    <meta name='referrer' content='strict-origin-when-cross-origin' />
    <meta name="viewport" content="width=device-width" />
    <link rel="icon" href="/wp-content/uploads/2023/09/favicon.ico" sizes="32x32" />
    <link rel="icon" href="/wp-content/uploads/2023/09/favicon.ico" sizes="192x192" />
    <link rel="apple-touch-icon" href="/wp-content/uploads/2023/09/favicon.ico" />
    <style type="text/css">
        body.login {{
            background: #f1f1f1;
            min-width: 0;
            color: #3c434a;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen-Sans, Ubuntu, Cantarell, "Helvetica Neue", sans-serif;
            font-size: 13px;
            line-height: 1.4em;
        }}
        body.login div#login {{
            width: 320px;
            padding: 8% 0 0;
            margin: auto;
        }}
        body.login div#login h1 {{
            text-align: center;
        }}
        body.login div#login h1 a {{
            background-image: url(data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iODQiIGhlaWdodD0iODQiIHZpZXdCb3g9IjAgMCA4NCA4NCIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KPHBhdGggZmlsbC1ydWxlPSJldmVub2RkIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGQ9Ik00MiAwQzY1LjE5NiAwIDg0IDE4LjgwNCA4NCA0MlM2NS4xOTYgODQgNDIgODRTMCA2NS4xOTYgMCA0MlMxOC44MDQgMCA0MiAwWiIgZmlsbD0iIzIxNzFCNSIvPgo8cGF0aCBkPSJNMTcuNSAyNS41SDE4VjU4LjVIMTcuNVYyNS41WiIgZmlsbD0id2hpdGUiLz4KPHBhdGggZD0iTTIxIDI1LjVIMjEuNVY1OC41SDIxVjI1LjVaIiBmaWxsPSJ3aGl0ZSIvPgo8L3N2Zz4K);
            background-size: 84px;
            background-position: center top;
            background-repeat: no-repeat;
            color: #3c434a;
            font-size: 20px;
            font-weight: 400;
            line-height: 1.3em;
            margin: 0 auto 25px;
            padding: 0;
            text-decoration: none;
            width: 84px;
            height: 84px;
            text-indent: -9999px;
            outline: 0;
            overflow: hidden;
            display: block;
        }}
        .login form {{
            margin-top: 20px;
            margin-left: 0;
            padding: 26px 24px 34px;
            font-weight: 400;
            overflow: hidden;
            background: #fff;
            border: 1px solid #c3c4c7;
            box-shadow: 0 1px 3px rgba(0,0,0,0.04);
        }}
        .login form .input, .login input[type=text] {{
            color: #2c3338;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen-Sans, Ubuntu, Cantarell, "Helvetica Neue", sans-serif;
            font-size: 24px;
            width: 100%;
            border: 1px solid #8c8f94;
            padding: 3px 5px;
            margin: 2px 6px 16px 0;
            min-height: 32px;
            max-height: none;
            background: #fbfbfc;
        }}
        .login form .input:focus {{
            border-color: #2271b1;
            box-shadow: 0 0 0 1px #2271b1;
            outline: 2px solid transparent;
        }}
        .login form p {{
            margin-bottom: 0;
        }}
        .login form .forgetmenot {{
            font-weight: 400;
            float: left;
            margin-bottom: 0;
        }}
        .login form .submit {{
            text-align: right;
            padding: 1px 0 0;
        }}
        .login form .submit .button-primary {{
            float: right;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen-Sans, Ubuntu, Cantarell, "Helvetica Neue", sans-serif;
            font-size: 13px;
            line-height: 2.15384615;
            min-height: 30px;
            padding: 0 12px;
            text-decoration: none;
            border: 1px solid #2271b1;
            background: #2271b1;
            color: #fff;
            cursor: pointer;
            border-radius: 3px;
        }}
        .login form .submit .button-primary:hover {{
            background: #135e96;
            border-color: #135e96;
        }}
        .login label {{
            color: #3c434a;
            font-size: 14px;
        }}
        .login #nav {{
            text-align: center;
            padding: 0 24px;
        }}
        .login #nav a {{
            text-decoration: none;
            color: #50575e;
            font-size: 13px;
        }}
        .login #nav a:hover {{
            color: #135e96;
        }}
        #loginform {{
            position: relative;
        }}
        .wp-pwd {{
            position: relative;
        }}
        .wp-pwd input[type=password], .wp-pwd input[type=text] {{
            padding-right: 40px;
        }}
        .wp-hide-pw {{
            position: absolute;
            right: 0.5rem;
            top: 0.5rem;
            color: #8c8f94;
            cursor: pointer;
            user-select: none;
        }}
        .privacy-policy-page-link {{
            text-align: center;
            margin: 3em 0 2em;
        }}
    </style>
</head>
<body class="login no-js login-action-login wp-core-ui  locale-en-us">
    <script type="text/javascript">
        document.body.className = document.body.className.replace('no-js','js');
    </script>
    <div id="login">
        <h1><a href="https://wordpress.org/">Powered by WordPress</a></h1>
        <form name="loginform" id="loginform" action="{0}" method="post">
            <p>
                <label for="user_login">Username or Email Address</label>
                <input type="text" name="log" id="user_login" class="input" value="" size="20" autocapitalize="off" autocomplete="username" required="required" autofocus="autofocus" />
            </p>
            <div class="user-pass-wrap">
                <label for="user_pass">Password</label>
                <div class="wp-pwd">
                    <input type="password" name="pwd" id="user_pass" class="input password-input" value="" size="20" autocomplete="current-password" spellcheck="false" required="required" />
                    <button type="button" class="wp-hide-pw hide-if-no-js" data-toggle="0" aria-label="Show password">
                        <span class="dashicons dashicons-visibility" aria-hidden="true"></span>
                    </button>
                </div>
            </div>
            <p class="forgetmenot"><input name="rememberme" type="checkbox" id="rememberme" value="forever"  /> <label for="rememberme">Remember Me</label></p>
            <p class="submit">
                <input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="Log In" />
                <input type="hidden" name="redirect_to" value="/wp-admin/" />
                <input type="hidden" name="testcookie" value="1" />
            </p>
        </form>
        <p id="nav">
            <a href="/wp-login.php?action=lostpassword">Lost your password?</a>
        </p>
        <script type="text/javascript">
        function wp_attempt_focus() {{
            setTimeout( function() {{
                try {{
                    d = document.getElementById('user_login');
                    d.focus(); d.select();
                }} catch(er) {{}}
            }}, 200);
        }}
        if(typeof wpOnload!=='function'){{wpOnload=function(){{}}}}
        if(typeof wpOnload!=='function'){{wpOnload=function(){{}}}}
        wpOnload();
        </script>
        <div class="privacy-policy-page-link"><a href="/privacy-policy/">Privacy Policy</a></div>
    </div>
    <div class="clear"></div>
</body>
</html>'''.format(self.path).encode()
        self.wfile.write(wordpress_login)

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode(errors='ignore')
        from urllib.parse import parse_qs
        creds = parse_qs(post_data)
        
        # Handle WordPress-style field names
        username = creds.get('log', [''])[0] or creds.get('username', [''])[0]  # WordPress uses 'log' field
        password = creds.get('pwd', [''])[0] or creds.get('password', [''])[0]  # WordPress uses 'pwd' field
        remember_me = creds.get('rememberme', [''])[0]
        
        # Log credentials as an attack
        log_data = {
            'username': username,
            'password': password,
            'remember_me': remember_me,
            'login_path': self.path,
            'user_agent': self.headers.get('User-Agent', ''),
            'referer': self.headers.get('Referer', '')
        }
        self.log_attack("http", log_data, payload=post_data)
        
        # Always return to login page with error (WordPress behavior)
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        
        # Generate authentic WordPress login error page
        wordpress_error = '''<!DOCTYPE html>
<html lang="en-US">
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
    <title>Log In &lsaquo; WordPress &mdash; WordPress</title>
    <link rel='dns-prefetch' href='//fonts.googleapis.com' />
    <link rel='dns-prefetch' href='//s.w.org' />
    <meta name='robots' content='max-image-preview:large' />
    <link rel='stylesheet' id='dashicons-css' href='/wp-includes/css/dashicons.min.css?ver=6.3.1' type='text/css' media='all' />
    <link rel='stylesheet' id='buttons-css' href='/wp-includes/css/buttons.min.css?ver=6.3.1' type='text/css' media='all' />
    <link rel='stylesheet' id='forms-css' href='/wp-admin/css/forms.min.css?ver=6.3.1' type='text/css' media='all' />
    <link rel='stylesheet' id='l10n-css' href='/wp-admin/css/l10n.min.css?ver=6.3.1' type='text/css' media='all' />
    <link rel='stylesheet' id='login-css' href='/wp-admin/css/login.min.css?ver=6.3.1' type='text/css' media='all' />
    <meta name='referrer' content='strict-origin-when-cross-origin' />
    <meta name="viewport" content="width=device-width" />
    <link rel="icon" href="/wp-content/uploads/2023/09/favicon.ico" sizes="32x32" />
    <style type="text/css">
        body.login {{
            background: #f1f1f1;
            min-width: 0;
            color: #3c434a;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen-Sans, Ubuntu, Cantarell, "Helvetica Neue", sans-serif;
            font-size: 13px;
            line-height: 1.4em;
        }}
        body.login div#login {{
            width: 320px;
            padding: 8% 0 0;
            margin: auto;
        }}
        body.login div#login h1 {{
            text-align: center;
        }}
        body.login div#login h1 a {{
            background-image: url(data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iODQiIGhlaWdodD0iODQiIHZpZXdCb3g9IjAgMCA4NCA4NCIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KPHBhdGggZmlsbC1ydWxlPSJldmVub2RkIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGQ9Ik00MiAwQzY1LjE5NiAwIDg0IDE4LjgwNCA4NCA0MlM2NS4xOTYgODQgNDIgODRTMCA2NS4xOTYgMCA0MlMxOC44MDQgMCA0MiAwWiIgZmlsbD0iIzIxNzFCNSIvPgo8cGF0aCBkPSJNMTcuNSAyNS41SDE4VjU4LjVIMTcuNVYyNS41WiIgZmlsbD0id2hpdGUiLz4KPHBhdGggZD0iTTIxIDI1LjVIMjEuNVY1OC41SDIxVjI1LjVaIiBmaWxsPSJ3aGl0ZSIvPgo8L3N2Zz4K);
            background-size: 84px;
            background-position: center top;
            background-repeat: no-repeat;
            color: #3c434a;
            font-size: 20px;
            font-weight: 400;
            line-height: 1.3em;
            margin: 0 auto 25px;
            padding: 0;
            text-decoration: none;
            width: 84px;
            height: 84px;
            text-indent: -9999px;
            outline: 0;
            overflow: hidden;
            display: block;
        }}
        .login form {{
            margin-top: 20px;
            margin-left: 0;
            padding: 26px 24px 34px;
            font-weight: 400;
            overflow: hidden;
            background: #fff;
            border: 1px solid #c3c4c7;
            box-shadow: 0 1px 3px rgba(0,0,0,0.04);
        }}
        .login form .input, .login input[type=text] {{
            color: #2c3338;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen-Sans, Ubuntu, Cantarell, "Helvetica Neue", sans-serif;
            font-size: 24px;
            width: 100%;
            border: 1px solid #8c8f94;
            padding: 3px 5px;
            margin: 2px 6px 16px 0;
            min-height: 32px;
            max-height: none;
            background: #fbfbfc;
        }}
        .login form .input:focus {{
            border-color: #2271b1;
            box-shadow: 0 0 0 1px #2271b1;
            outline: 2px solid transparent;
        }}
        .login form p {{
            margin-bottom: 0;
        }}
        .login form .forgetmenot {{
            font-weight: 400;
            float: left;
            margin-bottom: 0;
        }}
        .login form .submit {{
            text-align: right;
            padding: 1px 0 0;
        }}
        .login form .submit .button-primary {{
            float: right;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen-Sans, Ubuntu, Cantarell, "Helvetica Neue", sans-serif;
            font-size: 13px;
            line-height: 2.15384615;
            min-height: 30px;
            padding: 0 12px;
            text-decoration: none;
            border: 1px solid #2271b1;
            background: #2271b1;
            color: #fff;
            cursor: pointer;
            border-radius: 3px;
        }}
        .login form .submit .button-primary:hover {{
            background: #135e96;
            border-color: #135e96;
        }}
        .login label {{
            color: #3c434a;
            font-size: 14px;
        }}
        .login #nav {{
            text-align: center;
            padding: 0 24px;
        }}
        .login #nav a {{
            text-decoration: none;
            color: #50575e;
            font-size: 13px;
        }}
        .login #nav a:hover {{
            color: #135e96;
        }}
        #loginform {{
            position: relative;
        }}
        .wp-pwd {{
            position: relative;
        }}
        .wp-pwd input[type=password], .wp-pwd input[type=text] {{
            padding-right: 40px;
        }}
        .wp-hide-pw {{
            position: absolute;
            right: 0.5rem;
            top: 0.5rem;
            color: #8c8f94;
            cursor: pointer;
            user-select: none;
        }}
        .privacy-policy-page-link {{
            text-align: center;
            margin: 3em 0 2em;
        }}
        #login_error {{
            border-left: 4px solid #d63638;
            padding: 12px;
            margin-left: 0;
            margin-bottom: 20px;
            background-color: #fff;
            border-right: 1px solid #c3c4c7;
            border-top: 1px solid #c3c4c7;
            border-bottom: 1px solid #c3c4c7;
            box-shadow: 0 1px 1px rgba(0,0,0,0.04);
            word-wrap: break-word;
        }}
    </style>
</head>
<body class="login no-js login-action-login wp-core-ui  locale-en-us">
    <script type="text/javascript">
        document.body.className = document.body.className.replace('no-js','js');
    </script>
    <div id="login">
        <h1><a href="https://wordpress.org/">Powered by WordPress</a></h1>
        
        <div id="login_error">
            <strong>Error:</strong> The username or password you entered is incorrect. <a href="/wp-login.php?action=lostpassword">Lost your password?</a><br />
        </div>
        
        <form name="loginform" id="loginform" action="{0}" method="post">
            <p>
                <label for="user_login">Username or Email Address</label>
                <input type="text" name="log" id="user_login" class="input" value="{1}" size="20" autocapitalize="off" autocomplete="username" required="required" autofocus="autofocus" />
            </p>
            <div class="user-pass-wrap">
                <label for="user_pass">Password</label>
                <div class="wp-pwd">
                    <input type="password" name="pwd" id="user_pass" class="input password-input" value="" size="20" autocomplete="current-password" spellcheck="false" required="required" />
                    <button type="button" class="wp-hide-pw hide-if-no-js" data-toggle="0" aria-label="Show password">
                        <span class="dashicons dashicons-visibility" aria-hidden="true"></span>
                    </button>
                </div>
            </div>
            <p class="forgetmenot"><input name="rememberme" type="checkbox" id="rememberme" value="forever"  /> <label for="rememberme">Remember Me</label></p>
            <p class="submit">
                <input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="Log In" />
                <input type="hidden" name="redirect_to" value="/wp-admin/" />
                <input type="hidden" name="testcookie" value="1" />
            </p>
        </form>
        <p id="nav">
            <a href="/wp-login.php?action=lostpassword">Lost your password?</a>
        </p>
        <script type="text/javascript">
        function wp_attempt_focus() {{
            setTimeout( function() {{
                try {{
                    d = document.getElementById('user_login');
                    d.focus(); d.select();
                }} catch(er) {{}}
            }}, 200);
        }}
        if(typeof wpOnload!=='function'){{wpOnload=function(){{}}}}
        wpOnload();
        </script>
        <div class="privacy-policy-page-link"><a href="/privacy-policy/">Privacy Policy</a></div>
    </div>
    <div class="clear"></div>
</body>
</html>'''.format(self.path, username).encode()
        self.wfile.write(wordpress_error)
    # Duplicate do_GET removed. Only the main do_GET method remains above.

    def log_message(self, format, *args):
        # Suppress default logging
        return

class HTTPHoneypot:
    def __init__(self, host="0.0.0.0", port=8080):
        self.host = host
        self.port = port

    def run(self):
        print(f"[+] HTTP Honeypot listening on {self.host}:{self.port}")
        with socketserver.TCPServer((self.host, self.port), HTTPHoneypotHandler) as httpd:
            httpd.serve_forever()
