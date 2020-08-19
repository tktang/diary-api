
from http import HTTPStatus

from flask_jwt_extended import get_jwt_identity, jwt_optional, jwt_required
from flask_restful import Resource
from webargs.fields import Bool, Email, Int, Str
from webargs.flaskparser import use_kwargs

from api.models import Note, User


class NoteListResource(Resource):
    """Get all notes and create a new note"""

    @jwt_required
    def get(self, user_notes=None):
        current_user = get_jwt_identity()

        user_notes = Note.query.filter_by(user_id=current_user).first()

        notes = user_notes.get_all_published()
        data = []

        if notes:

            for note in notes:
                data.append(note.data())

            return {"data": data}, HTTPStatus.OK
        return {"msg": "no notes available"}, HTTPStatus.BAD_REQUEST

    @use_kwargs(
        {
            "title": Str(required=True, location="json"),
            "notes": Str(required=True, location="json"),
        }
    )
    @jwt_required
    def post(self, title, notes):

        current_user = get_jwt_identity()
        note = Note(title=title, notes=notes, user_id=current_user)
        saved_notes = note.save()
        
        return (
            {
                "msg": "successfully created notes",
                "data": {
                    "title_of_post": title,
                    "contents_of_post": notes,
                    "user_id": current_user,
                },
            },
            HTTPStatus.CREATED,
        )


class NoteResource(Resource):
    @use_kwargs(
        {
            "note_id": Int(location="path"),
            "title": Str(required=True, location="json"),
            "notes": Str(required=True, location="json"),
        }
    )
    @jwt_required
    def put(self, note_id, title, notes):

        note = Note.get_by_id(note_id=note_id)

        if note is None:
            return {"message": "Note not found"}, HTTPStatus.NOT_FOUND

        current_user = get_jwt_identity()

        if current_user != note.user_id:
            return {"message": "Access is not allowed"}, HTTPStatus.FORBIDDEN

        note.title = title
        note.notes = notes

        return (
            {"msg": "records updated successfully", "data": note.data()},
            HTTPStatus.OK,
        )

    @use_kwargs({"note_id": Int(location="path")})
    @jwt_required
    def delete(self, note_id):

        note = Note.get_by_id(note_id=note_id)

        if note is None:
            return {"message": "Note not found"}, HTTPStatus.NOT_FOUND

        current_user = get_jwt_identity()

        if current_user != note.user_id:
            return {"message": "Access is not allowed"}, HTTPStatus.FORBIDDEN

        note.delete()

        return {"msg": "action completed, note has been deleted"}, HTTPStatus.OK


class NotePublishResource(Resource):
    @use_kwargs({"note_id": Int(location="path")})
    @jwt_required
    def put(self, note_id):

        note = Note.get_by_id(note_id=note_id)

        if note is None:
            return {"message": "Note not found"}, HTTPStatus.NOT_FOUND

        current_user = get_jwt_identity()

        if current_user != note.user_id:
            return {"message": "Access is not allowed"}, HTTPStatus.FORBIDDEN

        note.publish = True
        note.save()

        return {"msg": "your note has been published succesfully"}, HTTPStatus.OK


class DraftNoteListResource(Resource):
    @jwt_required
    def get(self, user_notes=None):
        current_user = get_jwt_identity()

        user_notes = Note.query.filter_by(user_id=current_user).first()

        notes = user_notes.get_all_drafts()
        data = []

        if notes:

            for note in notes:
                data.append(note.data())

            return {"data": data}, HTTPStatus.OK
        return {"msg": "no notes available"}, HTTPStatus.BAD_REQUEST
