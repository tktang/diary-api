from marshmallow import (Schema, fields, post_dump, post_load, pre_load,
                         validate, ValidationError)
from werkzeug.security import check_password_hash, generate_password_hash




class UserSchema(Schema):
    class Meta:
        ordered = True

    id = fields.Int(dump_only=True)
    username = fields.String(required=True)
    email = fields.Email(required=True)
    password = fields.Method(
        required=True, deserialize="load_password"
    )

    created_at = fields.DateTime(dump_only=True)
    updated_at = fields.DateTime(dump_only=True)

    def load_password(self, value):
        return generate_password_hash(value)
    
    # Clean up data
    @pre_load
    def process_input(self, data, **kwargs):
        data["email"] = data["email"].lower().strip()
        return data
    

   



# def must_not_be_blank(data):
#     if not data:
#         raise ValidationError("Data not provided.")


# class NoteSchema(Schema):
   
#     id = fields.Integer(dump_only=True)
#     title = fields.String(required=True, validate=must_not_be_blank)
#     notes = fields.String()
#     publish = fields.Boolean(dump_only=True)
#     user = fields.Nested(UserSchema)
#     created_at = fields.DateTime(dump_only=True)
#     updated_at = fields.DateTime(dump_only=True)

    
    





