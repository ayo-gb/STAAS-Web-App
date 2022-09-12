from datetime import datetime
from email.policy import default
from flask import Flask, render_template, url_for, flash, redirect, request, abort
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import null
from forms import RegistrationForm, LoginForm, CreateFlowForm, DeleteFlowForm, UpdateAccountForm, CreateOfferedFlowForm, ModifyFlowForm, SelectFlowForm, ModifyOfferedFlowForm
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, current_user, logout_user, login_required, UserMixin

app = Flask(__name__)
app.config['SECRET_KEY'] = '5791628bb0b13ce0c676dfde280ba245'  # REDO SECRET KEY PROCESS
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model,  UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    is_admin = db.Column(db.Boolean, nullable=False, default=False)
    flows = db.relationship('Flow', backref='user', lazy=True)

    def __repr__(self):
        return f"User('{self.name}', '{self.email}')"
 

class Flow(db.Model):
    name = db.Column(db.String(100), nullable=False)
    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.Text, nullable=False)
    is_offered = db.Column(db.Boolean, nullable=False, default=False) #is the flow being offered by admin or recieved by non-admin
    status = db.Column(db.Boolean, nullable = False, default=True) # whether it's active or not
    destination_address = db.Column(db.Text, nullable=False, default='')
    destination_port = db.Column(db.Text, nullable=False, default='')
    source_flow = db.Column(db.Text, nullable=False, default='None') # base flow the user is accessing
    start_time = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False) # user that created flow
    port_type = db.Column(db.Text, nullable=False, default='') # flow specifiers
    selected_traffic = db.Column(db.Text, nullable=False, default='')
    payload_obfuscation =  db.Column(db.Text, nullable=False, default='')

    #ADMIN FLOWS ONLY- more flow specifiers
    source_address= db.Column(db.Text, nullable=False, default='')
    speed = db.Column(db.Integer, nullable=False, default=0)
    replication = db.Column(db.Text, nullable=False, default='')
    filters = db.Column(db.Text, nullable=False, default='None')


    def __repr__(self):
        return f"Flow('{self.id}', '{self.name}', '{self.start_time}')"



@app.before_first_request
def recreate_tables():
    db.drop_all()
    db.create_all()

@app.route("/")
@app.route("/home")
def home():
    flows = Flow.query.filter_by(is_offered=True).all()
    return render_template('home.html', flows=flows, title='Offered Flows')


@app.route("/about")
def about():
    return render_template('about.html', title='About')


@app.route("/user/flows")
def user_flows():
    flows = Flow.query.filter_by(user_id=current_user.id).all()
    return render_template('user_flows.html', title='User Flows', flows=flows)


@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(id=hashString(form.user_name.data), name=form.user_name.data, email=form.email.data, password=hashed_password)
        if '@princeton.edu' in form.email.data:
            user.is_admin = True
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)


@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title='Login', form=form)


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route("/account", methods=['GET', 'POST'])
@login_required
def account():
    form = UpdateAccountForm()
    if form.validate_on_submit():
        current_user.name = form.user_name.data
        current_user.email = form.email.data
        db.session.commit()
        flash('Your account has been updated!', 'success')
        return redirect(url_for('account'))
    elif request.method == 'GET':
        form.user_name.data = current_user.name
        form.email.data = current_user.email
    return render_template('account.html', title='Account', form=form)


@app.route("/flow/<int:flow_id>")
def flow(flow_id):
    flow = Flow.query.get_or_404(flow_id)
    return render_template('flow.html', title=flow.name, flow=flow)


@app.route("/flow/new", methods=['GET', 'POST'])
@login_required
def new_flow():
    if current_user.is_admin :
        form = CreateOfferedFlowForm()
        if form.validate_on_submit():
            flow = Flow(name = form.name.data,
                        id = hashString(form.name.data),
                        description = form.description.data,
                        source_address = form.source_address.data,
                        speed = form.speed.data,
                        replication = form.replication.data,
                        filters = form.filters.data,
                        is_offered= True,
                        user = current_user)
            db.session.add(flow)
            db.session.commit()
            flash('Your Flow has been Created', 'success')
            return redirect(url_for('user_flows'))
    else:
        form = CreateFlowForm()
        form.source_flow.choices = [f.name for f in Flow.query.filter_by(is_offered=True).all()] # Show Princeton-Offered Flows ONLY
        if form.validate_on_submit():
            flow = Flow(name = form.name.data,
                        id = hashString(form.name.data),
                        description = form.description.data,
                        destination_address = form.destination_address.data,
                        destination_port = form.destination_port.data,
                        source_flow = form.source_flow.data,
                        port_type = ','.join(form.port_type.data),
                        selected_traffic =  ','.join(form.selected_traffic.data),
                        payload_obfuscation =   ','.join(form.payload_obfuscation.data),
                        user = current_user)
            db.session.add(flow)
            db.session.commit()
            flash('Your Flow has been Created', 'success')
            return redirect(url_for('user_flows'))
    return render_template('create_flow.html', title='New Flow',
                           form=form, legend='New Flow')


@app.route("/flow/modify", methods=['GET', 'POST'])
@login_required
def modify_flow():
    first_form = SelectFlowForm()
    first_form.flow_selection.choices = [(f.id, f.name) for f in Flow.query.filter_by(user_id=current_user.id).all()] # Show User's Created Flows ONLY

    if first_form.validate_on_submit():
        flow = Flow.query.get_or_404(first_form.flow_selection.data)
        if flow.user_id != current_user.id:
            abort(403)
        return redirect(url_for('modify_flow_form', flow_id=flow.id))
    return render_template('modify_flow.html', title='Modify Flow', 
                            form=first_form, legend='Modify Flow')


@app.route("/flow/modify/<int:flow_id>", methods=['GET', 'POST'])
@login_required
def modify_flow_form(flow_id):
    flow = Flow.query.get_or_404(flow_id)
    if current_user.is_admin:
        form = ModifyOfferedFlowForm()
        if form.validate_on_submit():
            flow.description = form.description.data
            flow.source_address = form.source_address.data
            flow.speed= form.speed.data
            flow.replication = form.replication.data
            flow.filters = form.filters.data
            db.session.commit()
            flash('Your flow information has been updated', 'success')
            return redirect(url_for('user_flows'))
        elif request.method == 'GET':
            form.description.data = flow.description
            form.source_address.data = flow.source_address
            form.speed.data = flow.speed
            form.replication.data = flow.replication
            form.filters.data = flow.filters
    else:
        form = ModifyFlowForm()
        if form.validate_on_submit():
            flow.description = form.description.data
            flow.destination_address = form.destination_address.data
            flow.destination_port = form.destination_port.data
            flow.port_type = ','.join(form.port_type.data)
            flow.selected_traffic =  ','.join(form.selected_traffic.data)
            flow.payload_obfuscation =   ','.join(form.payload_obfuscation.data)
            if form.status.data == 'Active':
                prev_status = flow.status
                flow.status = True
                if not prev_status:
                    flow.start_time = datetime.utcnow
            else:
                flow.status = False
            db.session.commit()
            flash('Your flow information has been updated', 'success')
            return redirect(url_for('user_flows'))
        elif request.method == 'GET':
            form.description.data = flow.description
            form.destination_address.data = flow.destination_address
            form.destination_port.data = flow.destination_port
            form.port_type.data = flow.port_type.split(',')
            form.selected_traffic.data = flow.selected_traffic.split(',')
            form.payload_obfuscation.data = flow.payload_obfuscation.split(',')
            if flow.status:
                form.status.data = 'Active'
            else:
                form.status.data = 'Paused'
    return render_template('mod_flow_form.html', title='Modify Flow',
                           form=form, legend= f'Modify Flow: { flow.name }')


@app.route("/flows/delete", methods=['GET', 'POST'])
@login_required
def delete_flow():
    form = DeleteFlowForm()
    form.flows.choices = [f.id for f in Flow.query.filter_by(user_id=current_user.id).all()] # Show User's Created Flows ONLY

    if form.validate_on_submit():
        flow = Flow.query.get_or_404(form.flows.data)
        if flow.user_id != current_user.id:
            abort(403)
        db.session.delete(flow)
        db.session.commit()
        flash('Your Flow has been Deleted', 'success')
        return redirect(url_for('home'))
    return render_template('delete_flow.html', title='Delete Flow',
                           form=form, legend='Delete Flow')


# Used to create unique ids
def hashString(string):
    hash=0
    for i in range(len(string)):
        hash += ord(string[i]) * i
        hash = hash & hash
    return hash


if __name__ == '__main__':
    app.run(debug=True)
