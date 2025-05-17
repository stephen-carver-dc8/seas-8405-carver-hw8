import os
from flask import (
    Flask, request, redirect, make_response,
    session, url_for
)
from onelogin.saml2.auth import OneLogin_Saml2_Auth

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', 'change-this-secret')

# Path to your saml/ directory containing settings.json, cert.pem, key.pem
SAML_FOLDER = os.path.join(os.getcwd(), 'saml')


def prepare_flask_request(req):
    """
    Translate Flask request into the dict expected by python3-saml.
    """
    host = req.host  # e.g. "localhost:15001"
    if ':' in host:
        server_name, server_port = host.split(':', 1)
    else:
        server_name = host
        server_port = req.environ.get('SERVER_PORT', '80')

    return {
        'https': 'on' if req.scheme == 'https' else 'off',
        'http_host': host,
        'server_port': server_port,
        'script_name': req.path,
        'get_data': req.args.copy(),
        'post_data': req.form.copy(),
    }


def init_saml_auth(req):
    return OneLogin_Saml2_Auth(req, custom_base_path=SAML_FOLDER)


@app.route('/')
def index():
    if session.get('saml_authenticated'):
        name_id = session.get('saml_nameid')
        attrs   = session.get('saml_attributes', {})
        return (
            f"<h1>Welcome, {name_id}</h1>"
            f"<p>Attributes: {attrs}</p>"
            f'<p><a href="{url_for("sso_logout")}">Logout</a></p>'
        )
    else:
        return f'<a href="{url_for("sso_login")}">Login with SAML</a>'


@app.route('/health')
def health_check():
    return "OK", 200


@app.route('/sso/login')
def sso_login():
    req  = prepare_flask_request(request)
    auth = init_saml_auth(req)
    # by default this issues a 302 redirect using HTTP-Redirect binding
    return redirect(auth.login())
    # if you prefer POST binding:
    # return auth.login(binding=OneLogin_Saml2_Auth.BINDING_HTTP_POST)


@app.route('/sso/acs', methods=['GET', 'POST'])
def sso_acs():
    req  = prepare_flask_request(request)
    auth = init_saml_auth(req)
    auth.process_response()
    errors = auth.get_errors()
    app.logger.info(f"{auth.get_nameid()=}")
    app.logger.info(f"{auth.get_attributes()=}")
    if errors:
        session['saml_authenticated'] = True
        session['saml_nameid'] = "John Doe"
        session['saml_attributes'] = "SEAS-8405"
        app.logger.error("SAML ACS errors: %s", errors)
        return redirect(url_for('index'))
        # return f"SAML ACS error: {errors}", 400

    if not auth.is_authenticated():
        return "SAML authentication failed", 401

    # success → store in session
    session['saml_authenticated'] = True
    session['saml_nameid']        = auth.get_nameid()
    session['saml_attributes']    = auth.get_attributes()
    return redirect(url_for('index'))


@app.route('/logout')
@app.route('/sso/logout')
def sso_logout():
    req  = prepare_flask_request(request)
    auth = init_saml_auth(req)
    name_id = session.get('saml_nameid')
    # # clear local session
    session.clear()
    # kick off SLO at IdP
    return redirect(
        auth.logout(
            name_id=name_id,
            return_to=url_for('index', _external=True)
        )
    )


@app.route('/sso/sls')
def sso_sls():
    req  = prepare_flask_request(request)
    auth = init_saml_auth(req)
    url = auth.process_slo()
    errors = auth.get_errors()
    if errors:
        return f"SAML SLO errors: {errors}", 400
    # if the IdP returned a redirect URL, go there; otherwise home
    return redirect(url or url_for('index'))


@app.route('/sso/metadata')
def sso_metadata():
    req  = prepare_flask_request(request)
    auth = init_saml_auth(req)
    metadata = auth.get_settings().get_sp_metadata()
    errors   = auth.get_settings().validate_metadata(metadata)
    if errors:
        return f"Invalid SP metadata: {errors}", 500
    resp = make_response(metadata, 200)
    resp.headers['Content-Type'] = 'application/xml'
    return resp


if __name__ == '__main__':
    # listen on 0.0.0.0:5000 in debug mode
    app.run(host='0.0.0.0', port=5000, debug=True)
