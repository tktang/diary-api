import datetime
import json
import os
import unittest
from unittest import TestCase
import io

from flask import url_for
from flask_jwt_extended import create_access_token

from api.app import create_app
from api.models import User, db
from utils.email_token import confirm_token, generate_confirmation_token

# registration data
payload = {
    "email": "oluchi@gmail.com",
    "password": "#hdyuER456*&",
    "username": "oluchidfg",
}
# login details
login_details = {
    "email": "oluchi@gmail.com",
    "password": "#hdyuER456*&",
}


class UserTestCase(TestCase):
    def setUp(self):
        self.app = create_app("testing")
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()
        self.client = self.app.test_client(use_cookies=True)

    def tearDown(self):
        """
        Will be called after every test
        """
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def test_user_registration_login(self):

        # test user registration
        response = self.client.post(
            "/v1/user/register/",
            headers={"Content-Type": "application/json"},
            data=json.dumps(payload),
        )

        self.assertEqual(response.status_code, 201)
        self.assertEqual(User.query.count(), 1)
        user = User.query.filter_by(username="oluchidfg").first()
        self.assertEqual(user.confirmed, False)
        self.assertEqual(user.confirmed_on, None)

        # Try to login as a user before confirmation

        response = self.client.post(
            "/v1/user/login/",
            headers={"Content-Type": "application/json"},
            data=json.dumps(login_details),
        )
        self.assertTrue(
            "The user account is not activated yet" in response.get_data(as_text=True)
        )

        # now confirm the user
        user = User.query.filter_by(email="oluchi@gmail.com").first()
        token = generate_confirmation_token(user.email)
        response = self.client.get(
            "/users/activate/{}".format(token), follow_redirects=True
        )
        email = confirm_token(token)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            "The user account has been activated" in response.get_data(as_text=True)
        )

        # test user after email confirmation
        response = self.client.post(
            "/v1/user/login/",
            headers={"Content-Type": "application/json"},
            data=json.dumps(login_details),
        )
        res_data = response.json
        self.assertEqual(res_data["status"], "success")
        self.assertEqual(res_data["data"]["email"], "oluchi@gmail.com")
        self.assertEqual(res_data["data"]["user_id"], 1)
        self.assertEqual(response.status_code, 200)

        # test_login_with_invalid_password
        login_details["email"] = "oolluuu#@gmail.com"
        response = self.client.post(
            "/v1/user/login/",
            headers={"Content-Type": "application/json"},
            data=json.dumps(login_details),
        )
        self.assertTrue(
            "username or password is incorrect" in response.get_data(as_text=True)
        )
        # try to register user with existing email
        data = {
            "email": "oluchi@gmail.com",
            "password": "#hdyuER456*&",
            "username": "oluchidfggggg",
        }
        response = self.client.post(
            "/v1/user/register/",
            headers={"Content-Type": "application/json"},
            data=json.dumps(data),
        )
        res = response.json
        self.assertEqual(res["message"], "email already exist")
        self.assertEqual(response.status_code, 400)

        # try to register user with invalid email
        data = {
            "email": "oluchiiiigmail.com",
            "password": "#hdyuER456*&",
            "username": "oluchidfggggg",
        }
        response = self.client.post(
            "/v1/user/register/",
            headers={"Content-Type": "application/json"},
            data=json.dumps(data),
        )
        res = response.json
        self.assertEqual(res["errors"]["email"], ["Not a valid email address."])
        self.assertEqual(response.status_code, 422)

        # recover password after forgetting login details
        email = payload["email"]

        token = generate_confirmation_token(email)

        password_reset = {
            "password": "hgRT45&*efg&",
            "confirmation_password": "hgRT45&*efg&",
        }
        email = confirm_token(token)
        response = self.client.patch(
            "/users/reset_password/{}".format(token),
            headers={"Content-Type": "application/json"},
            data=json.dumps(password_reset),
        )

        res = response.json
        self.assertEqual(res["data"]["msg"], "New password was successfully set")
        self.assertEqual(response.status_code, 200)

        # try to reset password with 2 umatching passwords
        email = payload["email"]

        token = generate_confirmation_token(email)

        password_reset = {
            "password": "hgRT45&*efg&",
            "confirmation_password": "hgRT45&fff*efg&",
        }
        email = confirm_token(token)
        response = self.client.patch(
            "/users/reset_password/{}".format(token),
            headers={"Content-Type": "application/json"},
            data=json.dumps(password_reset),
        )

        res = response.json
        self.assertEqual(res["message"], "The two password do not match")
        self.assertEqual(response.status_code, 400)

    def test_display_image_upload(self):
        user = User(
            username="oluchiiii",
            email="oluchi@gmail.com",
            password="xy%^FD345Yyuu*9",
            confirmed=True,
            confirmed_on=datetime.datetime.now(),
        )

        db.session.add(user)
        db.session.commit()
        
        

        access_token = create_access_token(identity=user.id, fresh=True)
        
        #test empty file upload
        data = {}
        response = self.client.put(
        '/v1/user/display_image/', 
        headers={
                "Content-Type": "multipart/form-data",
                "Authorization": f"Bearer {access_token}",
            },data=data,follow_redirects=True,

        )
        
        self.assertEqual(response.status_code, 400)
        

        #test  file upload
        filedata = {'file' : (io.BytesIO(b"image"), 'style3.jpg')}
        response = self.client.put(
        '/v1/user/display_image/', 
        headers={
                "Content-Type": "multipart/form-data",
                "Authorization": f"Bearer {access_token}",
            },data=filedata,follow_redirects=True,

        )
        # res=response.json
        # self.assertEqual(res["msg"], "uploaded display image successfully")
        # self.assertEqual(response.status_code, 200)



        #get user info
        response = self.client.get(
            "/v1/user/user_info/",
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {access_token}",
            }
        )

        res = response.json
        self.assertEqual(res["message"], "welcome to your biodata page")
        self.assertNotEqual(res["email"], "The 6yy&*hgdgdjjdhhg")
        self.assertEqual(response.status_code, 200)

        
        