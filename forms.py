from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField, SelectMultipleField, SelectField, IntegerField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from flask_login import current_user


class RegistrationForm(FlaskForm):
    user_name = StringField('Name',
                           validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

class UpdateAccountForm(FlaskForm):
    user_name = StringField('Username',
                           validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    submit = SubmitField('Update')

    def validate_username(self, username):
        if username.data != current_user.username:
            user = User.query.filter_by(username=username.data).first()
            if user:
                raise ValidationError('That username is taken. Please choose a different one.')

    def validate_email(self, email):
        if email.data != current_user.email:
            user = User.query.filter_by(email=email.data).first()
            if user:
                raise ValidationError('That email is taken. Please choose a different one.')

class CreateFlowForm(FlaskForm):
    name = StringField('Flow Name',
                        validators=[DataRequired(), Length(min=2, max=40)])
    description = TextAreaField('Flow Description', validators=[DataRequired()])
    destination_address = StringField('Flow Destination Address (IPv4 Address)',
                        validators=[DataRequired(), Length(min=2, max=20)])
    destination_port = StringField('Flow Destination Port',
                        validators=[DataRequired(), Length(min=2, max=5)])
    source_flow = SelectField('Select Source Flow', validate_choice=False) # could be accessed through ID or Name
    port_type = SelectMultipleField('Select Port Type(s)', choices=['TCP', 'UDP', 'None']) 
    selected_traffic = SelectMultipleField('Select Traffic(s) to Forward', choices=['TCP', 'UDP', 'ICMP' ,'Any'])
    payload_obfuscation =  SelectMultipleField('Select Payload Obfuscation(s)', choices=['Mask', 'Slice', 'None'])
    submit = SubmitField('Create Flow')

class CreateOfferedFlowForm(FlaskForm):
    name = StringField('Flow Name',
                        validators=[DataRequired(), Length(min=2, max=40)])
    description = TextAreaField('Flow Description', validators=[DataRequired()])
    source_address = StringField('Flow Source Address (IPv4 Address)',
                        validators=[DataRequired(), Length(min=2, max=30)])
    filters = StringField('Specify Filters',
                        validators=[DataRequired(), Length(min=2, max=100)])
    speed = IntegerField('Flow Speed (Gbps)', validators=[DataRequired()])
    replication= SelectField('Select Replication Method', choices=['Tapped', 'Direct', 'Mirrored']) # could be accessed through ID or Name
    submit = SubmitField('Create Flow Offering')

class SelectFlowForm(FlaskForm):
    flow_selection = SelectField('Select Flow to Modify', validate_choice=False) # could be accessed through ID or Name
    submit = SubmitField('Select Flow')

class ModifyFlowForm(FlaskForm):
    status = SelectField('Modify Flow Status', choices=['Active', 'Paused'])
    description = TextAreaField('Flow Description', validators=[DataRequired()])
    destination_address = StringField('Flow Destination Address (IPv4 Address)',
                        validators=[DataRequired(), Length(min=2, max=20)])
    destination_port = StringField('Flow Destination Port',
                        validators=[DataRequired(), Length(min=2, max=5)])
    port_type = SelectMultipleField('Select Port Type(s)', choices=['TCP', 'UDP', 'None']) 
    selected_traffic = SelectMultipleField('Select Traffic(s) to Forward', choices=['TCP', 'UDP', 'ICMP' ,'Any'])
    payload_obfuscation =  SelectMultipleField('Select Payload Obfuscation(s)', choices=['Mask', 'Slice', 'None'])
    submit = SubmitField('Submit Flow Modifications', default=False)

class ModifyOfferedFlowForm(FlaskForm):
    description = TextAreaField('Flow Description', validators=[DataRequired()])
    source_address = StringField('Flow Source Address (IPv4 Address)',
                        validators=[DataRequired(), Length(min=2, max=30)])
    speed = IntegerField('Flow Speed (Gbps)', validators=[DataRequired()])
    filters = StringField('Specify Filters',
                        validators=[DataRequired(), Length(min=2, max=100)])
    replication= SelectField('Select Replication Method', choices=['Tapped', 'Direct', 'Mirrored']) # could be accessed through ID or Name
    submit = SubmitField('Submit Flow Modifications', default=False)

class DeleteFlowForm(FlaskForm):
    flows = SelectField('Select ID of Flow to Delete') # could be accessed through ID or Name
    submit = SubmitField('Delete Flow')
