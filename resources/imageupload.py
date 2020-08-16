from http import HTTPStatus

from flask import Flask, flash, redirect, request, url_for
from flask_jwt_extended import (create_access_token, create_refresh_token,
                                get_jwt_identity, get_raw_jwt, jwt_optional,
                                jwt_refresh_token_required, jwt_required)
from flask_restful import Api, Resource
from werkzeug.datastructures import FileStorage
from werkzeug.utils import secure_filename

# from api.models import User, FileUpload


api= Api()

# ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'gif','svg','bmp'])

# def allowed_file(filename):
#     return '.' in filename and \
#            filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# class UserImageUploadResource(Resource):

#     @jwt_required
#     def post(self, file):

#         if 'file' not in request.files:
#             return {'message': 'Upload an image'}, HTTPStatus.BAD_REQUEST

#         file = request.files['file']
#          # Check if the file is one of the allowed types/extensions
        
#         if isinstance(file, FileStorage) and allowed_file(file.filename):
#             # Make the filename safe, remove unsupported chars
#             filename = secure_filename(file.filename)
#             mimetype = file.content_type
#             print(filename)
#             print(mimetype)

#             current_user= get_jwt_identity()
#             file_upload = FileUpload(name=filename,
#                                         user_id=current_user,
#                                         extension=mimetype,
#                                         file=file.read())
#             saved_image = file_upload.save()
#             if saved_image:
                
#                 return { "msg": "successfully uploaded images"},HTTPStatus.CREATED
#             else:
#                 return { "msg": "an error occured in the database"},HTTPStatus.BAD_REQUEST
#         else:
#             return {'message': 'File type not allowed, upload png, jpeg, svg files'}, HTTPStatus.BAD_REQUEST

                
         
                







            

