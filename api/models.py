

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

db = SQLAlchemy()





class BaseModel(db.Model):
    """Define the base model for all other models."""

    __abstract__ = True
    id = db.Column(db.Integer(), primary_key=True)
    created_on = db.Column(db.DateTime(), server_default=db.func.now(), nullable=False)
    updated_on = db.Column(db.DateTime(),nullable=False,
                           server_default=db.func.now(),
                           onupdate=db.func.now())
    def save(self):
        """Save an instance of the model from the database."""
        try:
            db.session.add(self)
            db.session.commit()     
        except IntegrityError:
            db.session.rollback()
        except SQLAlchemyError:
            db.session.rollback()

    def update(self):
        """Update an instance of the model from the database."""
        return db.session.commit()


    def delete(self):
        """Delete an instance of the model from the database."""
        try:
            db.session.delete(self)
            db.session.commit()
        except SQLAlchemyError:
            db.session.rollback()
            
    


class User(BaseModel):
    __tablename__ = 'user'

    username = db.Column(db.String(80), nullable=False, unique=True)
    email = db.Column(db.String(200), nullable=False, unique=True)
    password = db.Column(db.String(200),nullable=False)
    note = db.relationship('Note', backref='user')
    
    
    @classmethod
    def get_by_username(cls, username):
        return cls.query.filter_by(username=username).first()

    @classmethod
    def get_by_email(cls, email):
        return cls.query.filter_by(email=email).first()


    @classmethod 
    def get_by_id(cls, id):                 
        return cls.query.filter_by(id=id).first()





class Note(BaseModel):
    __tablename__ = 'note'

    title = db.Column(db.String(100), nullable=False)
    notes = db.Column(db.String(1000))
    publish = db.Column(db.Boolean(), default=False)
    user_id = db.Column(db.Integer(), db.ForeignKey("user.id"),nullable=False)

    def data(self):
        return {
            'id': self.id,
            'title': self.title,
            'notes': self.notes,
            'user_id': self.user_id
        }

    @classmethod
    def get_all_published(cls):
        return cls.query.filter_by(publish=True).all()

    @classmethod
    def get_all_drafts(cls):
        return cls.query.filter_by(publish=False).all()


    @classmethod
    def get_by_id(cls, note_id):
        return cls.query.filter_by(id=note_id).first()
