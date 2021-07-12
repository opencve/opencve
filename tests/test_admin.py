import os
from wtforms import PasswordField, validators
from opencve.commands.create_user import create_user
from opencve.models.vendors import Vendor
import pytest
import datetime
from opencve.extensions import db
from opencve.models.users import User
from opencve.admin import AuthModelView
from opencve.admin import UserModelView
from opencve.extensions import CustomUserManager
from flask_user import UserManager
from flask_user.forms import EditUserProfileForm


def test_on_model_change_create_form(app, create_user):
    '''
    This method's goal is to detect password changes when the user is created. Flask_admin has
    hidden methods such as get_create_form() and get_edit_form() that allows for a way to create
    and add forms behind the scenes. I needed to create a user and pass in the user to the form in 
    order to create data points. I call the function with the associated parameters and do a check
    to see if the changed hashed password matches the original password. 
    '''

    user = create_user("opencve")
    object = UserModelView(User, db.session)
    form = UserModelView.get_create_form(object)
    form.create_password.data = 'create_password'
    object.on_model_change(form, user, True)
    
    # The commit was done after the change in password from the on_model_change method because 
    # the database values needed to be updated accordingly.

    db.session.commit()
    assert app.user_manager.verify_password('create_password', user.password) == True
    
    
def test_on_model_change_edit_form(app, create_user):
    '''
    This method's goal is to detect password changes when the user is created. However,
    in this case, there will be an edit_password method in use as the user will not be created 
    in this instance. Therefore, this is a similar process rather we will have to check the 
    edit_password.data rather than the create_password.data.
    '''

    user = create_user("app")
    object = UserModelView(User, db.session)
    form = UserModelView.get_edit_form(object)
    form.edit_password.data = 'edit_password'
    object._on_model_change(form, user, False)

    # The commit was done after the change in password from the on_model_change method because 
    # the database values needed to be updated accordingly.

    db.session.commit()
    assert app.user_manager.verify_password('edit_password', user.password) == True
    
