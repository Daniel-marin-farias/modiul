import json
import requests
from odoo import http
from odoo.http import request
from odoo.exceptions import AccessDenied

GOOGLE_TOKEN_INFO_URL = "https://oauth2.googleapis.com/tokeninfo"

class GoogleOneTapAuthController(http.Controller):

    @http.route('/google/authenticate', type='json', auth="public", csrf=False)
    def google_authenticate(self, **post):
        token = post.get("token")
        if not token:
            return {"success": False, "error": "Missing token"}

        # Validar token con Google
        response = requests.get(GOOGLE_TOKEN_INFO_URL, params={"id_token": token})
        if response.status_code != 200:
            return {"success": False, "error": "Invalid token"}

        user_info = response.json()
        email = user_info.get("email")
        name = user_info.get("name")

        if not email:
            return {"success": False, "error": "No email in token"}

        # Buscar o crear el usuario
        user = request.env["res.users"].sudo().search([("login", "=", email)], limit=1)
        if not user:
            user = request.env["res.users"].sudo().create({
                "name": name or email,
                "login": email,
                "email": email,
                "active": True,
                "groups_id": [(6, 0, [request.env.ref('base.group_portal').id])]
            })

        # Hacer login en sesión
        try:
            request.session.authenticate(request.env.cr.dbname, user.login, user._password or '')
        except AccessDenied:
            return {"success": False, "error": "Access denied"}

        return {"success": True}
