import datetime
import json
import os
import unittest
from unittest import TestCase

from api.app import create_app
from flask import url_for
from flask_jwt_extended import create_access_token
from api.models import User, db

# registration data


note_payload = {
    "title": "My Flask Testing",
    "notes": "I used Unittest LIbrary",
}


class NoteTestCase(TestCase):
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

    def test_notes(self):

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
        res = self.client.post(
            "/v1/notes/",
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {access_token}",
            },
            data=json.dumps(note_payload),
        )

        results = res.json
        self.assertEqual(results["msg"], "successfully created notes")
        self.assertEqual(results["data"]["title_of_post"], note_payload["title"])
        self.assertEqual(results["data"]["contents_of_post"], note_payload["notes"])
        self.assertEqual(res.status_code, 201)

        # get draft notes
        res = self.client.get(
            "/v1/notes/draft/",
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {access_token}",
            },
        )

        self.assertEqual(res.status_code, 200)

        # #let's publish the note
        res = self.client.put(
            "/v1/publish_note/1",
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {access_token}",
            },
        )

        results = res.json
        self.assertEqual(results["msg"], "your note has been published succesfully")
        self.assertEqual(res.status_code, 200)

        # update note
        note_payload["title"] = "Going to try Pytest"
        res = self.client.put(
            "/v1/notes/1",
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {access_token}",
            },
            data=json.dumps(note_payload),
        )

        results = res.json
        self.assertEqual(results["msg"], "records updated successfully")
        self.assertNotEqual(results["data"]["title"], "My Flask Testing")
        self.assertEqual(res.status_code, 200)
        # delete  a note
        res = self.client.delete(
            "/v1/notes/1",
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {access_token}",
            },
        )
        results = res.json
        self.assertEqual(results["msg"], "action completed, note has been deleted")
        # write to create a note without authorization
        res = self.client.post(
            "/v1/notes/",
            headers={"Content-Type": "application/json"},
            data=json.dumps(note_payload),
        )

        results = res.json

        self.assertEqual(results["message"], "Missing Authorization Header")
        self.assertEqual(res.status_code, 401)

       



    
