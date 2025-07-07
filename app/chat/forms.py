from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import TextAreaField, SubmitField

class MessageForm(FlaskForm):
    message = TextAreaField('Message')  # Optional
    file_data = FileField('Attach File', validators=[FileAllowed(['jpg', 'png', 'jpeg', 'gif', 'pdf', 'txt', 'doc', 'docx'])])
    submit = SubmitField('Send')